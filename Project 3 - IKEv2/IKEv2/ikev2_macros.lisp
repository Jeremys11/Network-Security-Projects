(defmacro (Certificate party pubkey_party ca)
    (cat party pubkey_party (enc (hash party pubkey_party) (privk ca))))