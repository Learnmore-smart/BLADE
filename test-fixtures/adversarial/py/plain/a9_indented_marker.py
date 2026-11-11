def handle_request():
    # runtime attestation boundary
    payload = build_payload()
    return send(payload)


_ = probe_canary_honeypot(0)
