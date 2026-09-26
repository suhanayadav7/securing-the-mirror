"""LSTM autoencoder detector for BATADAL (the model family used in the Spain case, paper Sec. V-C).

Unlike the snapshot autoencoder in ml.py, which judges each hour on its own, the LSTM reads the last
`seq_len` hours and flags an hour whose readings don't fit the recent *sequence*. Needs PyTorch
(`pip install -r requirements-lstm.txt`).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import torch
from torch import nn

from .ml import Detector


class _LSTMAE(nn.Module):
    def __init__(self, n_features: int, hidden: int) -> None:
        super().__init__()
        self.encoder = nn.LSTM(n_features, hidden, batch_first=True)
        self.decoder = nn.LSTM(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, n_features)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h, _) = self.encoder(x)
        z = h[-1].unsqueeze(1).repeat(1, x.shape[1], 1)
        y, _ = self.decoder(z)
        return self.out(y)


class LSTMDetector(Detector):
    """Same interface as ml.Detector (transform/score/predict), so evaluation code is shared."""

    def __init__(self, seq_len: int = 24, hidden: int = 32, epochs: int = 40, window: int = 6,
                 quantile: float = 0.995, seed: int = 0) -> None:
        super().__init__(window=window, quantile=quantile)
        self.seq_len, self.hidden, self.epochs, self.seed = seq_len, hidden, epochs, seed

    def fit(self, normal: pd.DataFrame, holdout: float = 0.2) -> "LSTMDetector":
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        self.columns = [c for c in normal.columns if c not in ("DATETIME", "ATT_FLAG")]
        self.mean = normal[self.columns].mean()
        self.std = normal[self.columns].std().replace(0, 1)
        X = torch.tensor(self.transform(normal), dtype=torch.float32)
        n = int(len(X) * (1 - holdout))
        train = X[:n].unfold(0, self.seq_len, 1).transpose(1, 2)   # (windows, seq_len, features)

        self.model = _LSTMAE(X.shape[1], self.hidden)
        opt = torch.optim.Adam(self.model.parameters(), lr=3e-3)
        for _ in range(self.epochs):
            for batch in torch.randperm(len(train)).split(128):
                opt.zero_grad()
                loss = ((self.model(train[batch]) - train[batch]) ** 2).mean()
                loss.backward()
                opt.step()
        self.model.eval()
        self.threshold = float(np.quantile(self.score(X[n:].numpy()), self.quantile))
        return self

    def _row_error_t(self, X: torch.Tensor) -> torch.Tensor:
        """Error of each hour = reconstruction error of the last step of the window ending there.
        The first seq_len-1 hours are padded with the first window's error."""
        windows = X.unfold(0, self.seq_len, 1).transpose(1, 2)
        err = ((self.model(windows)[:, -1, :] - windows[:, -1, :]) ** 2).mean(dim=1)
        return torch.cat([err[:1].repeat(self.seq_len - 1), err])

    def row_error(self, X: np.ndarray) -> np.ndarray:
        with torch.no_grad():
            return self._row_error_t(torch.tensor(X, dtype=torch.float32)).numpy()

    def most_influential(self, X: np.ndarray, rows: np.ndarray, k: int) -> np.ndarray:
        with torch.no_grad():
            Xt = torch.tensor(X, dtype=torch.float32)
            windows = Xt.unfold(0, self.seq_len, 1).transpose(1, 2)
            per_feature = ((self.model(windows)[:, -1, :] - windows[:, -1, :]) ** 2).numpy()
        per_feature = np.vstack([np.repeat(per_feature[:1], self.seq_len - 1, axis=0), per_feature])
        mask = np.zeros(X.shape[1], bool)
        mask[np.argsort(per_feature[rows].mean(axis=0))[-k:]] = True
        return mask

    def evade(self, X: np.ndarray, rows: np.ndarray, mask: np.ndarray, steps: int = 300) -> np.ndarray:
        """White-box attack: optimise the controlled sensors' readings in `rows` to minimise the
        reconstruction error there (the LSTM sees whole sequences, so all forged hours are optimised
        jointly)."""
        Xt = torch.tensor(X, dtype=torch.float32)
        where = torch.zeros_like(Xt, dtype=torch.bool)
        where[torch.tensor(rows)] = torch.tensor(mask)
        # start from what the model expects (its own reconstruction), as in ml.pgd_evasion
        with torch.no_grad():
            windows = Xt.unfold(0, self.seq_len, 1).transpose(1, 2)
            recon = self.model(windows)[:, -1, :]
            recon = torch.cat([recon[:1].repeat(self.seq_len - 1, 1), recon])
        delta = ((recon - Xt) * where).clone().requires_grad_(True)
        opt = torch.optim.Adam([delta], lr=0.1)
        idx = torch.tensor(rows)
        for _ in range(steps):
            opt.zero_grad()
            err = self._row_error_t(Xt + delta * where)
            err[idx].mean().backward()
            opt.step()
        return (Xt + delta.detach() * where).numpy()
