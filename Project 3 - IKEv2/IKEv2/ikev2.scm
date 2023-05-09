(herald "IKEv2")

(include "ikev2_macros.lisp")


;;SK = hash(nonceInit nonceRecv diffie-hellman shared secret(KEi KEr))
;;KEi = pubk Init
;;KEr = pubk resp
;;AUTH Responder = nonceInit + IDResponder 
;;AUTH INIT = responderNonce + IDInit
;;Just use ca as CERTREQ

(defprotocol ikev2 basic
    (defrole initiator
        (vars
            (IKEheader SAi1 SAr1 SAi2 SAr2 TSi TSr data)
            (initiator responder certificateAuthority name)
            (NonceInit NonceRecv text)
        )
        (trace
            ;;HDR, SAi1, KEi, Ni
            (send (cat IKEheader SAi1 (pubk initiator) NonceInit))

            ;;HDR, SAr1, KEr, Nr, [CERTREQ]
            (recv (cat IKEheader SAr1 (pubk responder) NonceRecv certificateAuthority))

            ;;HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr}
            (send 
                (cat 
                    IKEheader
                    (enc
                        initiator 
                        (Certificate initiator (pubk initiator) certificateAuthority) 
                        certificateAuthority
                        responder 
                        (hash NonceRecv initiator) ;;AUTH INIT = nonceRecv + IDInit
                        SAi2 
                        TSi 
                        TSr
                        (hash NonceInit NonceRecv (pubk responder) (pubk initiator))
                    )
                )
            );;End send

            ;;HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
            (recv 
                (cat 
                    IKEheader 
                    (enc 
                        responder 
                        (Certificate responder (pubk responder) certificateAuthority) 
                        (hash NonceRecv initiator) ;;AUTH INIT = responderNonce + IDInit
                        SAr2 
                        TSi 
                        TSr 
                        (hash NonceInit NonceRecv (pubk initiator) (pubk responder))
                    )
                )
            );;End recv
        )
    )

    (defrole responder
        (vars
            (IKEheader SAi1 SAr1 SAi2 SAr2 TSi TSr data)
            (initiator responder certificateAuthority name)
            (NonceInit NonceRecv text)
        )
        (trace
            ;;HDR, SAi1, KEi, Ni
            (recv (cat IKEheader SAi1 (pubk initiator) NonceInit))

            ;;HDR, SAr1, KEr, Nr, [CERTREQ]
            (send (cat IKEheader SAr1 (pubk responder) NonceRecv certificateAuthority))

            ;;HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr}
            (recv 
                (cat 
                    IKEheader 
                    (enc 
                        initiator 
                        (Certificate initiator (pubk initiator) certificateAuthority) 
                        certificateAuthority 
                        responder 
                        (hash NonceInit responder) ;;AUTH Responder = NonceInit + IDResponder 
                        SAi2 
                        TSi 
                        TSr 
                        (hash NonceInit NonceRecv (pubk responder) (pubk initiator)) ;;SK
                    )
                )
            );;End recv

            ;;HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
            (send 
                (cat 
                    IKEheader 
                    (enc
                        responder 
                        (Certificate responder (pubk responder) certificateAuthority) 
                        (hash NonceInit responder) ;;AUTH Responder = NonceInit + IDResponder 
                        SAr2 
                        TSi 
                        TSr 
                        (hash NonceInit NonceRecv (pubk initiator) (pubk responder))
                    )
                )
            );;End send
        )
    )
)



;;For initiator
;;Depth 4
(defskeleton ikev2
    (vars
        (initiator responder certificateAuthority name)
        (NonceInit text)
    )
    (defstrand initiator 4 
        (initiator initiator) (responder responder) (certificateAuthority certificateAuthority)
        (NonceInit NonceInit)
    )
    (uniq-orig NonceInit)
)

;;For responder
;;Depth 4
(defskeleton ikev2
    (vars
        (initiator responder certificateAuthority name)
        (NonceRecv text)
    )
    (defstrand responder 4  
        (initiator initiator) (responder responder) (certificateAuthority certificateAuthority)
        (NonceRecv NonceRecv) 
    )
    (uniq-orig NonceRecv)
)