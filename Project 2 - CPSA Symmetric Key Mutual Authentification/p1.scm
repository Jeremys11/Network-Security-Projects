;This is a comment
(herald "Protocol 1")

;Bob doing the authentication
;with encryption
;basic algebra
(defprotocol p1e basic

    ;Alice
    (defrole init
        (vars (a b name) (r text))
        (trace
            (send a)
            (recv r)
            ;ltk -- long term key
            (send (enc r (ltk a b)));not the same as ltk b a -- directional -- ORDER IS IMPORTANT
        )
    )

    ;Bob
    (defrole resp
        (vars (a b name) (r text))
        (trace
            (recv a)
            (send r)
            ;ltk -- long term key
            (recv (enc r (ltk a b)));not the same as ltk b a -- directional -- ORDER IS IMPORTANT   
        )
    )
)

;Examining Skeleton
(defskeleton p1e
    (vars (r text) (alice bob name)) ;r is type text -- alice bob type name
    ;r should be fresh
    (defstrand resp 3 (r r) (a alice) (b bob)) ;assigning variables
    (uniq-orig r)
    (non-orig (ltk alice bob))
)

;with hash
;(defprotocol p1h)