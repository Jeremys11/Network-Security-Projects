(herald "Protocol1")

;; A -> AS
;; identity A // Identity B // Nonce for transaction IA1

;; AS -> A
;; AS Creates conversation key CK
;; {nonce A // Identity B // conversation key CK,  {conversation key CK, identity A}**Key B  }**Key A

;; A -> B
;; {Conversation Key CK, Identity A}**Key B

;; B -> A
;; {Nonce B}**Conversation Key CK

;; A -> B
;; {Nonce B - 1}**Conversation Key CK

(defprotocol protocol1 basic
    (defrole authserv ;;AS
        (vars (a b as name) (nonceA text) (session_key skey))
        (trace
            ;; identity A // Identity B // Nonce for transaction IA1
            (recv (cat a b nonceA))

            ;; {nonce A // Identity B // conversation key CK,  {conversation key CK, identity A}**Key B  }**Key A
            (send (enc nonceA b session_key (enc session_key a (ltk b as)) (ltk a as)))
        )
        (uniq-orig session_key)
    )
    (defrole server ;;B
        (vars (a b as name) (nonceB text) (session_key skey))
        (trace
            ;;Recieve ticket portion of message from AS from A
            (recv (enc session_key a (ltk b as)))
            ;;Send nonce encrypted with session key
            (send (enc nonceB session_key))
            ;;Recieve modified nonce encrypted under session key
            (recv (enc (hash nonceB) session_key))
        )
    )
    (defrole client ;;A
        (vars (a b as name) (nonceA nonceB text) (tkt_as mesg) (session_key skey))
        (trace
            ;; identity A // Identity B // Nonce for transaction IA1
            (send (cat a b nonceA))
            ;;Recieving ticket under its own variable
            (recv (enc nonceA b session_key tkt_as (ltk a as)))
            ;;A sends ticket from as to b
            (send (cat tkt_as))
            ;;A recieves nonceB encrypted under session key
            (recv (enc nonceB session_key))
            ;;Send modified nonce encrypted under session key
            (send (enc (hash nonceB) session_key))
        )
    )
)

;;For server -- NOT AUTHENTICATING SERVER
;;Depth 3
(defskeleton protocol1
    (vars (a b as name) (nonceB text))
    (defstrand server 3 (a a) (as as) (b b) (nonceB nonceB))
    (non-orig (ltk a as) (ltk b as))
    (uniq-orig nonceB)
)

;;For client
;;Depth 5
(defskeleton protocol1 
    (vars (a b as name) (nonceA text))
    (defstrand client 5 (a a) (as as) (b b) (nonceA nonceA))
    (non-orig (ltk a as) (ltk b as))
    (uniq-orig nonceA)
)