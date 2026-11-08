"""
TrustLens Chain Module

Decentralized threat intelligence & on-chain verification.
Supports both live EVM RPC and local reproducible hash-chained ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from trustlens.config import Settings, get_settings
from trustlens.db import compute_report_hash, get_report, save_report
from trustlens.models import Assessment

# Try to import web3, but don't require it
try:
    from web3 import Web3
    from web3.exceptions import Web3Exception

    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    Web3 = None
    Web3Exception = Exception

# Contract ABI for ThreatRegistry
THREAT_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportIdHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "targetFingerprint", "type": "bytes32"},
            {"internalType": "uint8", "name": "classificationCode", "type": "uint8"},
            {"internalType": "uint8", "name": "score", "type": "uint8"},
        ],
        "name": "anchorReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportIdHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "expectedReportHash", "type": "bytes32"},
        ],
        "name": "verifyReport",
        "outputs": [
            {"internalType": "bool", "name": "exists", "type": "bool"},
            {"internalType": "bool", "name": "matches", "type": "bool"},
            {"internalType": "uint64", "name": "timestamp", "type": "uint64"},
            {"internalType": "address", "name": "reporter", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "reportIdHash", "type": "bytes32"},
            {"indexed": True, "internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"indexed": True, "internalType": "bytes32", "name": "targetFingerprint", "type": "bytes32"},
            {"indexed": False, "internalType": "uint8", "name": "classificationCode", "type": "uint8"},
            {"indexed": False, "internalType": "uint8", "name": "score", "type": "uint8"},
            {"indexed": True, "internalType": "address", "name": "reporter", "type": "address"},
            {"indexed": False, "internalType": "uint64", "name": "timestamp", "type": "uint64"},
        ],
        "name": "ReportAnchored",
        "type": "event",
    },
]


# Classification code mapping
CLASSIFICATION_CODE = {
    "low_risk": 0,
    "suspicious": 1,
    "high_risk": 2,
    "confirmed_malicious": 3,
    "inconclusive": 4,
}


def _get_chain_ledger_path(db_path: str) -> Path:
    """Get the path to the local chain ledger file."""
    return Path(db_path).with_suffix(".chain.json")


def _load_local_ledger(db_path: str) -> list[dict]:
    """Load the local hash-chained ledger."""
    ledger_path = _get_chain_ledger_path(db_path)
    if not ledger_path.exists():
        return []
    try:
        with open(ledger_path, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_local_ledger(db_path: str, ledger: list[dict]) -> None:
    """Save the local hash-chained ledger atomically."""
    ledger_path = _get_chain_ledger_path(db_path)
    # Write to temp file then rename for atomicity
    temp_path = ledger_path.with_suffix(".tmp")
    with open(temp_path, "w") as f:
        json.dump(ledger, f, indent=2)
    temp_path.replace(ledger_path)


def _compute_prev_block_hash(ledger: list[dict]) -> str:
    """Compute the hash of the previous block (or genesis)."""
    if not ledger:
        return "0x" + "0" * 64
    last = ledger[-1]
    # Hash the entire last block entry
    block_json = json.dumps(last, separators=(",", ":"), sort_keys=True)
    return "0x" + hashlib.sha256(block_json.encode("utf-8")).hexdigest()


def _generate_tx_hash(report_id: str, report_hash: str, target_fingerprint: str, timestamp: int) -> str:
    """Generate a deterministic transaction hash for local ledger."""
    data = f"{report_id}{report_hash}{target_fingerprint}{timestamp}"
    return "0x" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def _get_classification_code(classification) -> int:
    """Get numeric code for classification."""
    if hasattr(classification, "value"):
        return CLASSIFICATION_CODE.get(classification.value, 4)
    return CLASSIFICATION_CODE.get(str(classification), 4)


def _rpc_available(settings: Settings) -> bool:
    """Check if live EVM RPC is available and configured."""
    if not WEB3_AVAILABLE:
        return False
    if not settings.rpc_url or not settings.contract_address or not settings.private_key:
        return False
    try:
        w3 = Web3(Web3.HTTPProvider(settings.rpc_url, request_kwargs={"timeout": 5}))
        return w3.is_connected()
    except Exception:
        return False


def _anchor_via_rpc(
    settings: Settings,
    report_id_hash: bytes,
    report_hash: bytes,
    target_fingerprint: bytes,
    classification_code: int,
    score: int,
) -> str:
    """Anchor report via live EVM RPC. Returns tx_hash."""
    w3 = Web3(Web3.HTTPProvider(settings.rpc_url))
    account = w3.eth.account.from_key(settings.private_key)
    w3.eth.default_account = account.address

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(settings.contract_address),
        abi=THREAT_REGISTRY_ABI,
    )

    # Build transaction
    nonce = w3.eth.get_transaction_count(account.address)
    tx = contract.functions.anchorReport(
        report_id_hash,
        report_hash,
        target_fingerprint,
        classification_code,
        score,
    ).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "gas": 200000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )

    signed_tx = w3.eth.account.sign_transaction(tx, settings.private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt.status != 1:
        raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")

    return tx_hash.hex()


def _verify_via_rpc(
    settings: Settings,
    report_id_hash: bytes,
    expected_report_hash: bytes,
) -> tuple[bool, bool, int, str]:
    """Verify report via live EVM RPC. Returns (exists, matches, timestamp, reporter)."""
    w3 = Web3(Web3.HTTPProvider(settings.rpc_url))
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(settings.contract_address),
        abi=THREAT_REGISTRY_ABI,
    )
    result = contract.functions.verifyReport(report_id_hash, expected_report_hash).call()
    return result[0], result[1], result[2], result[3]


def anchor_report(assessment: Assessment, settings: Settings | None = None) -> dict:
    """
    Anchor a threat assessment report.

    Supports two modes:
    1. Live EVM RPC (if RPC_URL, CONTRACT_ADDRESS, PRIVATE_KEY configured and reachable)
    2. Local reproducible hash-chained ledger (default, always works)

    Args:
        assessment: The assessment to anchor
        settings: Optional settings (uses cached if not provided)

    Returns:
        Dict with tx_hash, report_hash, target_fingerprint, mode, and contract_address (if EVM)
    """
    if settings is None:
        settings = get_settings()

    # Ensure assessment has report_id and report_hash
    if assessment.report_id is None:
        raise ValueError("Assessment must have a report_id (save to DB first)")
    if assessment.report_hash is None:
        assessment.report_hash = compute_report_hash(assessment)

    report_hash = assessment.report_hash
    target_fingerprint = "0x" + hashlib.sha256(assessment.target.encode("utf-8")).hexdigest()
    classification_code = _get_classification_code(assessment.classification)
    score = assessment.score
    report_id_hash = hashlib.sha256(assessment.report_id.encode("utf-8")).digest()

    # Try live EVM RPC first
    if _rpc_available(settings):
        try:
            tx_hash = _anchor_via_rpc(
                settings,
                report_id_hash,
                bytes.fromhex(report_hash[2:]),
                bytes.fromhex(target_fingerprint[2:]),
                classification_code,
                score,
            )
            # Update assessment with tx_hash
            assessment.tx_hash = tx_hash
            save_report(assessment, db_path=settings.db_path)
            return {
                "tx_hash": tx_hash,
                "report_hash": report_hash,
                "target_fingerprint": target_fingerprint,
                "mode": "evm_rpc",
                "contract_address": settings.contract_address,
            }
        except Exception:
            # Fall through to local ledger on any RPC error
            pass

    # Local reproducible hash-chained ledger mode
    db_path = settings.db_path
    ledger = _load_local_ledger(db_path)
    block_number = len(ledger) + 1
    prev_block_hash = _compute_prev_block_hash(ledger)
    timestamp = int(time.time())

    tx_hash = _generate_tx_hash(assessment.report_id, report_hash, target_fingerprint, timestamp)

    entry = {
        "block_number": block_number,
        "tx_hash": tx_hash,
        "prev_block_hash": prev_block_hash,
        "report_id": assessment.report_id,
        "report_hash": report_hash,
        "target_fingerprint": target_fingerprint,
        "classification": assessment.classification.value if hasattr(assessment.classification, "value") else str(assessment.classification),
        "score": score,
        "timestamp": timestamp,
    }
    ledger.append(entry)
    _save_local_ledger(db_path, ledger)

    # Update assessment with tx_hash in SQLite (direct update to avoid duplicate insert)
    assessment.tx_hash = tx_hash
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE reports SET tx_hash = ?, assessment_json = ? WHERE report_id = ?",
            (tx_hash, json.dumps(assessment.model_dump(mode="json")), assessment.report_id),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "tx_hash": tx_hash,
        "report_hash": report_hash,
        "target_fingerprint": target_fingerprint,
        "mode": "local_ledger",
        "block_number": block_number,
    }


def verify_on_chain(report_id: str, settings: Settings | None = None) -> dict:
    """
    Verify a report's on-chain / hash-chained commitment.

    Args:
        report_id: The report ID to verify
        settings: Optional settings (uses cached if not provided)

    Returns:
        Verification result dict with integrity_verified flag
    """
    if settings is None:
        settings = get_settings()

    # Load report from SQLite
    assessment = get_report(report_id, db_path=settings.db_path)
    if assessment is None:
        raise ValueError(f"Report not found: {report_id}")

    stored_hash = assessment.report_hash
    recomputed_hash = compute_report_hash(assessment)

    # Compute target fingerprint
    target_fingerprint = "0x" + hashlib.sha256(assessment.target.encode("utf-8")).hexdigest()
    report_id_hash = hashlib.sha256(report_id.encode("utf-8")).digest()

    tx_hash = assessment.tx_hash
    on_chain_hash = None
    anchored = False

    # Try live EVM RPC verification
    if _rpc_available(settings) and tx_hash:
        try:
            exists, matches, timestamp, reporter = _verify_via_rpc(
                settings,
                report_id_hash,
                bytes.fromhex(stored_hash[2:]) if stored_hash else b"\x00" * 32,
            )
            if exists:
                anchored = True
                on_chain_hash = stored_hash if matches else "mismatch"
        except Exception:
            pass

    # Fall back to local ledger verification
    if not anchored and tx_hash:
        ledger = _load_local_ledger(settings.db_path)
        for entry in ledger:
            if entry["report_id"] == report_id and entry["tx_hash"] == tx_hash:
                anchored = True
                on_chain_hash = entry["report_hash"]
                break

    integrity_verified = (
        stored_hash is not None
        and recomputed_hash == stored_hash
        and (on_chain_hash == stored_hash or on_chain_hash is None)
    )

    return {
        "report_id": report_id,
        "stored_hash": stored_hash,
        "recomputed_hash": recomputed_hash,
        "on_chain_hash": on_chain_hash,
        "tx_hash": tx_hash,
        "target_fingerprint": target_fingerprint,
        "anchored": anchored,
        "integrity_verified": integrity_verified,
        "provenance_note": "Cryptographic commitment verifies report integrity and history, not the ground-truth validity of the underlying claim.",
    }