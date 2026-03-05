from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from flask import Flask, render_template, request, redirect, url_for, flash

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as rsa_padding


app = Flask(__name__)
app.secret_key = os.urandom(24)  # pour flash()

HASH_ALGOS = ["sha256", "sha512", "sha1", "md5"]


# -------------------------
# Helpers (Base64 / JSON)
# -------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def jcanon(obj: Any) -> bytes:
    """JSON canonique (stable) pour signer/hasher."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_ts() -> float:
    return time.time()


def short(s: str, n: int = 14) -> str:
    return s if len(s) <= n else s[:n] + "…"


# -------------------------
# Blockchain demo state
# -------------------------
STATE: Dict[str, Any] = {
    "difficulty": 4,
    "block_reward": 50.0,
    "accounts": [],   # list[dict]
    "mempool": [],    # list[dict] tx
    "chain": [],      # list[dict] blocks
    "nodes": ["Node A", "Node B", "Node C", "Node D", "Node E"],
}


def compute_address_from_pubkey_pem(public_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(pub_der)[:16]  # adresse courte (démo)


def genesis_block() -> Dict[str, Any]:
    block = {
        "index": 0,
        "timestamp": now_ts(),
        "previous_hash": "0" * 64,
        "nonce": 0,
        "difficulty": STATE["difficulty"],
        "miner": "GENESIS",
        "transactions": [],
    }
    block["hash"] = block_hash(block)
    return block


def block_hash(block: Dict[str, Any]) -> str:
    blk = dict(block)
    blk.pop("hash", None)
    return sha256_hex(jcanon(blk))


def init_chain_if_needed() -> None:
    if not STATE["chain"]:
        STATE["chain"] = [genesis_block()]


def get_balances_from_chain() -> Dict[str, float]:
    balances: Dict[str, float] = {}
    for blk in STATE["chain"]:
        for tx in blk["transactions"]:
            apply_tx_to_balances(tx, balances)
    # arrondir un peu pour l'affichage
    for k in list(balances.keys()):
        balances[k] = float(f"{balances[k]:.8f}")
    return balances


def total_supply() -> float:
    supply = 0.0
    for blk in STATE["chain"]:
        for tx in blk["transactions"]:
            if tx.get("type") == "coinbase":
                supply += float(tx["amount"])
    return float(f"{supply:.8f}")


def apply_tx_to_balances(tx: Dict[str, Any], balances: Dict[str, float]) -> None:
    tx_type = tx.get("type", "transfer")
    to_addr = tx["to"]
    amount = float(tx["amount"])
    fee = float(tx.get("fee", 0.0))

    balances.setdefault(to_addr, 0.0)
    balances[to_addr] += amount

    if tx_type != "coinbase":
        from_addr = tx["from"]
        balances.setdefault(from_addr, 0.0)
        balances[from_addr] -= (amount + fee)


def sign_payload_ecdsa(private_pem: str, payload: Dict[str, Any]) -> str:
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    sig = private_key.sign(jcanon(payload), ec.ECDSA(hashes.SHA256()))
    return b64e(sig)


def verify_payload_ecdsa(public_pem: str, payload: Dict[str, Any], signature_b64: str) -> Tuple[bool, str]:
    try:
        public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        public_key.verify(b64d(signature_b64), jcanon(payload), ec.ECDSA(hashes.SHA256()))
        return True, "OK"
    except Exception as e:
        return False, f"Signature invalide ({e})"


def validate_tx(tx: Dict[str, Any], balances: Dict[str, float]) -> Tuple[bool, str]:
    tx_type = tx.get("type", "transfer")

    # champs de base
    for k in ["to", "amount", "timestamp", "txid"]:
        if k not in tx:
            return False, f"Champ manquant: {k}"

    amount = float(tx["amount"])
    fee = float(tx.get("fee", 0.0))
    if amount <= 0:
        return False, "Montant doit être > 0"
    if fee < 0:
        return False, "Fee doit être >= 0"

    if tx_type == "coinbase":
        # pas de signature, "from" doit être COINBASE
        if tx.get("from") != "COINBASE":
            return False, "Coinbase invalide"
        return True, "OK"

    # transfer
    for k in ["from", "public_key_pem", "signature_b64", "fee"]:
        if k not in tx:
            return False, f"Champ manquant: {k}"

    from_addr = tx["from"]
    pub_pem = tx["public_key_pem"]

    # adresse doit correspondre à la clé publique
    expected_addr = compute_address_from_pubkey_pem(pub_pem)
    if expected_addr != from_addr:
        return False, "Adresse source ne correspond pas à la clé publique"

    # signature
    payload = {
        "from": tx["from"],
        "to": tx["to"],
        "amount": float(tx["amount"]),
        "fee": float(tx["fee"]),
        "timestamp": tx["timestamp"],
    }
    ok, msg = verify_payload_ecdsa(pub_pem, payload, tx["signature_b64"])
    if not ok:
        return False, msg

    # funds
    balances.setdefault(from_addr, 0.0)
    if balances[from_addr] < (amount + fee):
        return False, "Solde insuffisant"

    return True, "OK"


def validate_block(block: Dict[str, Any]) -> Tuple[bool, str]:
    # hash correct + difficulté
    computed = block_hash(block)
    if computed != block.get("hash"):
        return False, "Hash du bloc incorrect"
    if not block["hash"].startswith("0" * int(block["difficulty"])):
        return False, "Difficulté non respectée"

    # prev_hash correct
    if block["index"] == 0:
        return True, "OK"
    prev = STATE["chain"][-1]
    if block["previous_hash"] != prev["hash"]:
        return False, "previous_hash ne correspond pas au dernier bloc"

    # transactions valides (avec balances simulées dans l'ordre)
    balances = get_balances_from_chain()

    for tx in block["transactions"]:
        ok, msg = validate_tx(tx, balances)
        if not ok:
            return False, f"TX invalide: {msg}"
        apply_tx_to_balances(tx, balances)

    return True, "OK"


def make_coinbase_tx(miner_addr: str, reward_plus_fees: float) -> Dict[str, Any]:
    payload = {
        "from": "COINBASE",
        "to": miner_addr,
        "amount": float(reward_plus_fees),
        "fee": 0.0,
        "timestamp": now_ts(),
    }
    txid = sha256_hex(jcanon(payload))
    return {
        "type": "coinbase",
        **payload,
        "txid": txid,
    }


def make_transfer_tx(from_addr: str, to_addr: str, amount: float, fee: float, pub_pem: str, priv_pem: str) -> Dict[str, Any]:
    payload = {
        "from": from_addr,
        "to": to_addr,
        "amount": float(amount),
        "fee": float(fee),
        "timestamp": now_ts(),
    }
    sig_b64 = sign_payload_ecdsa(priv_pem, payload)
    txid = sha256_hex(jcanon(payload) + b64d(sig_b64))
    return {
        "type": "transfer",
        **payload,
        "public_key_pem": pub_pem,
        "signature_b64": sig_b64,
        "txid": txid,
    }


def candidate_transactions(limit: int = 10) -> List[Dict[str, Any]]:
    txs = sorted(STATE["mempool"], key=lambda t: float(t.get("fee", 0.0)), reverse=True)
    return txs[:limit]


def mine_next_block(miner_addr: str) -> Dict[str, Any]:
    init_chain_if_needed()

    prev = STATE["chain"][-1]
    txs = candidate_transactions()

    fees = sum(float(t.get("fee", 0.0)) for t in txs)
    coinbase = make_coinbase_tx(miner_addr, float(STATE["block_reward"]) + fees)

    # ordre du bloc : coinbase puis txs
    block_txs = [coinbase] + txs

    block = {
        "index": prev["index"] + 1,
        "timestamp": now_ts(),
        "previous_hash": prev["hash"],
        "nonce": 0,
        "difficulty": int(STATE["difficulty"]),
        "miner": miner_addr,
        "transactions": block_txs,
    }

    target_prefix = "0" * int(STATE["difficulty"])
    nonce = 0
    start = time.time()
    while True:
        block["nonce"] = nonce
        h = block_hash(block)
        if h.startswith(target_prefix):
            block["hash"] = h
            break
        nonce += 1

    block["mining_time_sec"] = float(f"{(time.time() - start):.4f}")
    return block


def avg_block_time() -> float:
    chain = STATE["chain"]
    if len(chain) < 3:
        return 0.0
    times = []
    for i in range(2, len(chain)):
        times.append(chain[i]["timestamp"] - chain[i - 1]["timestamp"])
    return float(f"{(sum(times) / len(times)):.4f}") if times else 0.0


# -------------------------
# Pages Crypto (déjà chez toi)
# -------------------------
@app.route("/")
def home():
    return redirect(url_for("basics_page"))


@app.route("/hash", methods=["GET", "POST"])
def hash_page():
    hashed = None
    error = None
    text = ""
    algo = "sha256"

    if request.method == "POST":
        text = request.form.get("text", "")
        algo = request.form.get("algo", "sha256").lower()

        if not text.strip():
            error = "Veuillez entrer un texte."
        elif len(text) > 10000:
            error = "Texte trop long (max 10 000 caractères)."
        elif algo not in HASH_ALGOS:
            error = "Algorithme invalide."
        else:
            h = hashlib.new(algo)
            h.update(text.encode("utf-8"))
            hashed = h.hexdigest()

    return render_template("hash.html", active="hash", hashed=hashed, error=error, text=text, algo=algo, algos=HASH_ALGOS)


@app.route("/symmetric", methods=["GET", "POST"])
def symmetric_page():
    error = None
    enc_key = enc_nonce = enc_ciphertext = ""
    dec_plaintext = ""

    plaintext = ""
    key_in = nonce_in = ciphertext_in = ""

    if request.method == "POST":
        action = request.form.get("action", "")

        try:
            if action == "encrypt":
                plaintext = request.form.get("plaintext", "")
                if not plaintext.strip():
                    raise ValueError("Veuillez entrer un message à chiffrer.")

                key_in = request.form.get("key", "").strip()
                if key_in:
                    key = b64d(key_in)
                    if len(key) != 32:
                        raise ValueError("Clé invalide : AES-256 = 32 octets (Base64).")
                else:
                    key = os.urandom(32)

                nonce = os.urandom(12)
                aesgcm = AESGCM(key)
                ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

                enc_key = b64e(key)
                enc_nonce = b64e(nonce)
                enc_ciphertext = b64e(ct)

            elif action == "decrypt":
                key_in = request.form.get("key", "").strip()
                nonce_in = request.form.get("nonce", "").strip()
                ciphertext_in = request.form.get("ciphertext", "").strip()

                if not key_in or not nonce_in or not ciphertext_in:
                    raise ValueError("Veuillez fournir clé, nonce et ciphertext.")

                key = b64d(key_in)
                nonce = b64d(nonce_in)
                ct = b64d(ciphertext_in)

                if len(key) != 32:
                    raise ValueError("Clé invalide : AES-256 = 32 octets.")
                if len(nonce) != 12:
                    raise ValueError("Nonce invalide : attendu 12 octets.")

                aesgcm = AESGCM(key)
                pt = aesgcm.decrypt(nonce, ct, None)
                dec_plaintext = pt.decode("utf-8", errors="replace")

            else:
                raise ValueError("Action invalide.")

        except Exception as e:
            error = str(e)

    return render_template(
        "symmetric.html",
        active="symmetric",
        error=error,
        plaintext=plaintext,
        key_in=key_in,
        nonce_in=nonce_in,
        ciphertext_in=ciphertext_in,
        enc_key=enc_key,
        enc_nonce=enc_nonce,
        enc_ciphertext=enc_ciphertext,
        dec_plaintext=dec_plaintext,
    )


@app.route("/asymmetric", methods=["GET", "POST"])
def asymmetric_page():
    error = None

    public_key_pem = private_key_pem = ""
    encrypted_key_b64 = enc_nonce_b64 = enc_ciphertext_b64 = ""
    decrypted_plaintext = ""

    message = ""
    pub_in = priv_in = ""
    in_encrypted_key = in_nonce = in_ciphertext = ""

    if request.method == "POST":
        action = request.form.get("action", "")

        try:
            if action == "generate":
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                priv_bytes = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_bytes = key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                private_key_pem = priv_bytes.decode("utf-8")
                public_key_pem = pub_bytes.decode("utf-8")

            elif action == "encrypt":
                message = request.form.get("message", "")
                pub_in = request.form.get("public_key", "")

                if not message.strip():
                    raise ValueError("Veuillez entrer un message.")
                if not pub_in.strip():
                    raise ValueError("Veuillez coller une clé publique PEM.")

                public_key = serialization.load_pem_public_key(pub_in.encode("utf-8"))

                aes_key = os.urandom(32)
                nonce = os.urandom(12)
                aesgcm = AESGCM(aes_key)
                ct = aesgcm.encrypt(nonce, message.encode("utf-8"), None)

                enc_key = public_key.encrypt(
                    aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                encrypted_key_b64 = b64e(enc_key)
                enc_nonce_b64 = b64e(nonce)
                enc_ciphertext_b64 = b64e(ct)

            elif action == "decrypt":
                priv_in = request.form.get("private_key", "")
                in_encrypted_key = request.form.get("encrypted_key", "").strip()
                in_nonce = request.form.get("nonce", "").strip()
                in_ciphertext = request.form.get("ciphertext", "").strip()

                if not priv_in.strip():
                    raise ValueError("Veuillez coller une clé privée PEM.")
                if not in_encrypted_key or not in_nonce or not in_ciphertext:
                    raise ValueError("Veuillez fournir encrypted_key, nonce et ciphertext.")

                private_key = serialization.load_pem_private_key(priv_in.encode("utf-8"), password=None)

                enc_key = b64d(in_encrypted_key)
                nonce = b64d(in_nonce)
                ct = b64d(in_ciphertext)

                aes_key = private_key.decrypt(
                    enc_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                aesgcm = AESGCM(aes_key)
                pt = aesgcm.decrypt(nonce, ct, None)
                decrypted_plaintext = pt.decode("utf-8", errors="replace")

            else:
                raise ValueError("Action invalide.")

        except Exception as e:
            error = str(e)

    return render_template(
        "asymmetric.html",
        active="asymmetric",
        error=error,
        public_key_pem=public_key_pem,
        private_key_pem=private_key_pem,
        message=message,
        pub_in=pub_in,
        priv_in=priv_in,
        encrypted_key_b64=encrypted_key_b64,
        enc_nonce_b64=enc_nonce_b64,
        enc_ciphertext_b64=enc_ciphertext_b64,
        in_encrypted_key=in_encrypted_key,
        in_nonce=in_nonce,
        in_ciphertext=in_ciphertext,
        decrypted_plaintext=decrypted_plaintext,
    )


# -------------------------
# Blockchain Demo Pages
# -------------------------
@app.route("/basics")
def basics_page():
    init_chain_if_needed()
    stats = {
        "difficulty": int(STATE["difficulty"]),
        "avg_block_time": avg_block_time(),
        "block_count": len(STATE["chain"]),
        "total_supply": total_supply(),
        "mempool_count": len(STATE["mempool"]),
        "block_reward": float(STATE["block_reward"]),
    }
    last_blocks = list(reversed(STATE["chain"][-6:]))
    return render_template("basics.html", active="basics", stats=stats, last_blocks=last_blocks)


@app.route("/accounts", methods=["GET", "POST"])
def accounts_page():
    init_chain_if_needed()

    if request.method == "POST":
        name = request.form.get("name", "").strip() or "Account"
        # ECDSA SECP256K1 (classique blockchain)
        private_key = ec.generate_private_key(ec.SECP256K1())
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        addr = compute_address_from_pubkey_pem(pub_pem)

        STATE["accounts"].append({
            "name": name,
            "address": addr,
            "public_key_pem": pub_pem,
            "private_key_pem": priv_pem,
            "created_at": now_ts(),
        })
        flash("Compte créé.")
        return redirect(url_for("accounts_page"))

    balances = get_balances_from_chain()
    return render_template("accounts.html", active="accounts", accounts=STATE["accounts"], balances=balances)


@app.route("/mempool", methods=["GET", "POST"])
def mempool_page():
    init_chain_if_needed()

    if request.method == "POST":
        if not STATE["accounts"]:
            flash("Crée au moins un compte avant d'ajouter une transaction.")
            return redirect(url_for("accounts_page"))

        sender = request.form.get("sender", "").strip()
        receiver = request.form.get("receiver", "").strip()
        amount = float(request.form.get("amount", "0") or 0)
        fee = float(request.form.get("fee", "0") or 0)

        if sender == receiver:
            flash("Sender et receiver doivent être différents.")
            return redirect(url_for("mempool_page"))

        from_acc = next((a for a in STATE["accounts"] if a["address"] == sender), None)
        to_acc = next((a for a in STATE["accounts"] if a["address"] == receiver), None)
        if not from_acc or not to_acc:
            flash("Compte introuvable.")
            return redirect(url_for("mempool_page"))

        balances = get_balances_from_chain()
        balances.setdefault(sender, 0.0)

        if amount <= 0:
            flash("Amount doit être > 0.")
            return redirect(url_for("mempool_page"))
        if fee < 0:
            flash("Fee doit être >= 0.")
            return redirect(url_for("mempool_page"))
        if balances[sender] < (amount + fee):
            flash("Solde insuffisant (chain).")
            return redirect(url_for("mempool_page"))

        tx = make_transfer_tx(
            from_addr=sender,
            to_addr=receiver,
            amount=amount,
            fee=fee,
            pub_pem=from_acc["public_key_pem"],
            priv_pem=from_acc["private_key_pem"],
        )

        # re-valider
        ok, msg = validate_tx(tx, balances)
        if not ok:
            flash(f"Transaction refusée: {msg}")
            return redirect(url_for("mempool_page"))

        STATE["mempool"].append(tx)
        flash("Transaction ajoutée au mempool.")
        return redirect(url_for("mempool_page"))

    balances = get_balances_from_chain()
    txs = sorted(STATE["mempool"], key=lambda t: float(t.get("fee", 0.0)), reverse=True)
    return render_template("mempool.html", active="mempool", accounts=STATE["accounts"], balances=balances, txs=txs)


@app.route("/mining", methods=["GET", "POST"])
def mining_page():
    init_chain_if_needed()

    mined_block = None
    consensus_report = None

    miner_addr = request.values.get("miner", "").strip()
    if not miner_addr and STATE["accounts"]:
        miner_addr = STATE["accounts"][0]["address"]

    if request.method == "POST":
        if not miner_addr:
            flash("Choisis un miner account.")
            return redirect(url_for("mining_page"))

        block = mine_next_block(miner_addr)

        ok, msg = validate_block(block)
        if not ok:
            flash(f"Bloc miné mais invalide: {msg}")
            return redirect(url_for("mining_page"))

        # ajouter à la chaîne
        included_txids = {t["txid"] for t in block["transactions"] if t.get("type") == "transfer"}
        STATE["mempool"] = [t for t in STATE["mempool"] if t["txid"] not in included_txids]
        STATE["chain"].append(block)

        mined_block = block
        flash(f"Bloc #{block['index']} miné en {block['mining_time_sec']}s.")

    # candidate (preview)
    cand = candidate_transactions()
    fees = sum(float(t.get("fee", 0.0)) for t in cand)
    cand_preview = {
        "tx_count": len(cand),
        "fees": float(f"{fees:.8f}"),
        "reward": float(STATE["block_reward"]),
        "total_payout": float(f"{(float(STATE['block_reward']) + fees):.8f}"),
    }

    return render_template(
        "mining.html",
        active="mining",
        accounts=STATE["accounts"],
        miner_addr=miner_addr,
        candidate=cand,
        cand_preview=cand_preview,
        mined_block=mined_block,
    )


@app.route("/blockchain")
def blockchain_page():
    init_chain_if_needed()
    blocks = list(reversed(STATE["chain"]))
    return render_template("blockchain.html", active="blockchain", blocks=blocks)


@app.route("/balances")
def balances_page():
    init_chain_if_needed()
    balances = get_balances_from_chain()
    return render_template("balances.html", active="balances", balances=balances, accounts=STATE["accounts"])


@app.route("/consensus", methods=["GET", "POST"])
def consensus_page():
    init_chain_if_needed()

    miner_addr = request.values.get("miner", "").strip()
    if not miner_addr and STATE["accounts"]:
        miner_addr = STATE["accounts"][0]["address"]

    report = None
    if request.method == "POST":
        if not miner_addr:
            flash("Choisis un miner account.")
            return redirect(url_for("consensus_page"))

        # On mine un bloc candidat, puis on simule les votes
        block = mine_next_block(miner_addr)

        votes = []
        for node in STATE["nodes"]:
            ok, msg = validate_block(block)
            votes.append({"node": node, "ok": ok, "msg": msg})

        accepted = sum(1 for v in votes if v["ok"])
        rejected = len(votes) - accepted
        majority = accepted > rejected

        report = {
            "block": block,
            "votes": votes,
            "accepted": accepted,
            "rejected": rejected,
            "majority": majority,
        }

        if majority:
            included_txids = {t["txid"] for t in block["transactions"] if t.get("type") == "transfer"}
            STATE["mempool"] = [t for t in STATE["mempool"] if t["txid"] not in included_txids]
            STATE["chain"].append(block)
            flash(f"Consensus OK : bloc #{block['index']} ajouté.")
        else:
            flash("Consensus KO : bloc rejeté.")

    cand = candidate_transactions()
    fees = sum(float(t.get("fee", 0.0)) for t in cand)

    return render_template(
        "consensus.html",
        active="consensus",
        accounts=STATE["accounts"],
        miner_addr=miner_addr,
        candidate=cand,
        fees=float(f"{fees:.8f}"),
        report=report,
        nodes=STATE["nodes"],
    )


@app.route("/internals")
def internals_page():
    init_chain_if_needed()
    data = {
        "difficulty": STATE["difficulty"],
        "block_reward": STATE["block_reward"],
        "accounts": [{"name": a["name"], "address": a["address"], "public_key_pem": a["public_key_pem"]} for a in STATE["accounts"]],
        "mempool": STATE["mempool"],
        "chain": STATE["chain"],
    }
    pretty = json.dumps(data, indent=2, ensure_ascii=False)
    return render_template("internals.html", active="internals", raw_json=pretty)


@app.route("/sign", methods=["GET", "POST"])
def sign_page():
    init_chain_if_needed()
    error = None

    message = ""
    private_pem = ""
    public_pem = ""
    signature_b64 = ""
    verify_ok = None
    verify_msg = ""

    if request.method == "POST":
        action = request.form.get("action", "")

        try:
            if action == "sign":
                message = request.form.get("message", "")
                private_pem = request.form.get("private_key", "")

                if not message.strip():
                    raise ValueError("Message manquant.")
                if not private_pem.strip():
                    raise ValueError("Clé privée manquante (PEM).")

                payload = {"message": message}
                signature_b64 = sign_payload_ecdsa(private_pem, payload)

                # dériver la clé publique depuis la privée (pour aider)
                priv = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
                public_pem = priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")

            elif action == "verify":
                message = request.form.get("message", "")
                public_pem = request.form.get("public_key", "")
                signature_b64 = request.form.get("signature", "").strip()

                if not message.strip() or not public_pem.strip() or not signature_b64:
                    raise ValueError("Message, clé publique et signature sont requis.")

                payload = {"message": message}
                ok, msg = verify_payload_ecdsa(public_pem, payload, signature_b64)
                verify_ok = ok
                verify_msg = msg

            else:
                raise ValueError("Action invalide.")

        except Exception as e:
            error = str(e)

    return render_template(
        "sign.html",
        active="sign",
        error=error,
        message=message,
        private_pem=private_pem,
        public_pem=public_pem,
        signature_b64=signature_b64,
        verify_ok=verify_ok,
        verify_msg=verify_msg,
    )


if __name__ == "__main__":
    init_chain_if_needed()
    app.run(debug=True)
