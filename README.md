# MISAKA Network Devnet
git clone https://github.com/MISAKA-BTC/MISAKA-devnet
cd misaka-core-rs-v9-stealth-hardening

cargo build --release

./target/release/misaka-node --network devnet
![MISAKA](https://img.shields.io/badge/network-devnet-blue)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-experimental-red)

MISAKA Network は **Rustで開発された量子耐性・プライバシー志向の Layer1 ブロックチェーン**です。

このリポジトリでは **Devnet（開発者ネットワーク）** のノード・CLI・ウォレット機能を提供します。

開発者や研究者は以下を実行できます。

* ノード起動
* トランザクション送信
* stealthトランザクション実験
* バリデータ参加

⚠ Devnetは実験環境です。
実際の資産は送らないでください。

---

# 🚀 MISAKAの特徴

MISAKA Network は次世代のブロックチェーン研究を目的としています。

特徴

* Rustでゼロから開発されたL1
* ポスト量子暗号
* stealthアドレスによるプライバシー
* 軽量バリデータ
* 高速ブロック生成
* 将来のDeFi / Web3拡張

---

# 🔐 使用暗号

MISAKAでは以下の暗号を使用しています。

### Falcon

ポスト量子署名アルゴリズム

### ML-KEM (Kyber)

ポスト量子鍵共有

### Stealth Address

受信者のアドレスを公開せず送金可能

---

# ⚡ クイックスタート（3分）

```bash
git clone https://github.com/YOUR_REPO/misaka-core
cd misaka-core
cargo build --release
./target/release/misaka-node --network devnet
```

これでノードが起動します。

---

# 🖥 必要環境

最低

CPU
2コア

RAM
4GB

SSD
20GB

推奨

CPU
4コア以上

RAM
8GB以上

SSD
50GB以上

---

# 🔧 Rustインストール

```bash
curl https://sh.rustup.rs -sSf | sh
```

確認

```bash
rustc --version
cargo --version
```

---

# 📂 ソース取得

```bash
git clone https://github.com/YOUR_REPO/misaka-core
cd misaka-core
```

---

# ⚙ ビルド

```bash
cargo build --release
```

生成

```
target/release/misaka-node
target/release/misaka-cli
```

---

# 🌐 ノード起動

```bash
./target/release/misaka-node \
--network devnet \
--data-dir ./data
```

---

# 🌍 Devnet接続

Seed Node

```
seed.misaka.network:8333
```

接続

```bash
./misaka-node \
--network devnet \
--seed-node seed.misaka.network:8333
```

---

# 📊 ノード状態

```bash
./misaka-cli status
```

例

```
network: devnet
peers: 8
block height: 1324
sync: true
```

---

# 👛 ウォレット作成

```bash
./misaka-cli wallet create
```

出力例

```
wallet created

address:
misaka1xxxxx

view key:
xxxxx

spend key:
xxxxx
```

⚠ 秘密鍵は安全に保管してください

---

# 💰 残高確認

```bash
./misaka-cli wallet balance
```

例

```
confirmed: 1000 MISAKA
pending: 0
```

---

# 🪙 Devnetトークン

DevnetトークンはFaucetから取得予定

```
https://faucet.misaka.network
```

またはDiscordで配布

---

# 💸 送金

```bash
./misaka-cli send \
--to ADDRESS \
--amount 10
```

例

```bash
./misaka-cli send \
--to misaka1abc... \
--amount 10
```

---

# 🔍 トランザクション確認

```bash
./misaka-cli tx TXID
```

---

# 🕶 stealth送金

MISAKAでは stealth address を利用して
受信者のアドレスを公開せず送金できます。

ウォレットは view key を使って
受信トランザクションを検出します。

スキャン

```bash
./misaka-cli wallet scan
```

---

# 🧱 バリデータ

起動

```bash
./misaka-node \
--network devnet \
--validator \
--data-dir ./validator
```

推奨

CPU
4コア

RAM
8GB

SSD
100GB

---

# 🧾 バリデータ登録

```bash
./misaka-cli validator register
```

---

# 🌐 ネットワーク情報

```bash
./misaka-cli network info
```

---

# 📜 Devnetパラメータ

Block Time
2秒

Block Size
32MB

Signature
Falcon

Stealth Encryption
ML-KEM

---

# 🧪 開発

テスト

```bash
cargo test
```

フォーマット

```bash
cargo fmt
```

Lint

```bash
cargo clippy
```

---

# 🗺 ロードマップ

### Devnet

* 基本ネットワーク
* stealthトランザクション
* validator

### Testnet

* faucet
* stress test
* wallet

### Mainnet

* 本格運用
* validator economics
* ecosystem

---

# 🤝 コントリビュート

以下の分野で貢献歓迎

* Rust開発
* 暗号
* ネットワーク
* ウォレット
* ノード性能

---

# 🌎 コミュニティ

Website
[https://misakabtc.com](https://misakabtc.com)

Discord
[https://discord.gg/zkDaVf2s](https://discord.gg/zkDaVf2s)

---

# 📄 License

MIT License

---

