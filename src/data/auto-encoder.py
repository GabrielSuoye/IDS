import numpy as np
import torch
from torch import nn
from torch import optim


class PacketAutoencoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(3, 2), nn.ReLU(), nn.Linear(2, 1))
        self.decoder = nn.Sequential(nn.Linear(1, 2), nn.ReLU(), nn.Linear(2, 3))

    def forward(self, x):
        return self.decoder(self.encoder(x))


print("Generating synthetic 'Normal' network data for Tier 3 training...")
np.random.seed(42)

# Features: [packets_per_sec, unique_dst_ips, avg_packet_len]
#  Autoencoders are trained ONLY on normal patterns so they fail on anomalies
normal_data = np.random.multivariate_normal(
    [15, 2, 64], [[2, 0.5, 0], [0.5, 0.5, 0], [0, 0, 10]], 2000
)
X_train = torch.tensor(normal_data, dtype=torch.float32)

# Train the network
model = PacketAutoencoder()
criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=0.01)

print("Training Tier 3 PyTorch Autoencoder...")
model.train()
for epoch in range(100):
    optimizer.zero_grad()
    outputs = model(X_train)
    loss = criterion(outputs, X_train)
    loss.backward()
    optimizer.step()

    if (epoch + 1) % 20 == 0:
        print(f"    Epoch [{epoch + 1}/100], Loss: {loss.item():.4f}")

# Save the weights to disk
torch.save(model.state_dict(), "autoencoder_ids.pth")
print("Tier 3 model weights successfully saved as 'autoencoder_ids.pth'.")
