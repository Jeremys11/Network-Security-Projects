(herald "Protocol1Intercept")

(defprotocol protocol1Intercept basic

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
  
  (defrole intruder ;;C
      (vars (a b name) (nonceA nonceB text) (session_key skey))
      (trace
          ;; Intercepts message Y from A to B
          (recv (cat a b nonceA))
          ;; Intercepts message from B to A requesting handshake
          (recv (enc nonceB session_key))
          ;; Impersonates A's response with modified nonce
          (send (enc (hash nonceB) session_key))
      )
  )
)

;;For client
;;Depth 5
(defskeleton protocol1Intercept
    (vars (a b as name) (nonceA text))
    (defstrand client 5 (a a) (as as) (b b) (nonceA nonceA))
    (non-orig (ltk a as) (ltk b as))
    (uniq-orig nonceA)
)

;;For server -- NOT AUTHENTICATING SERVER
;;Depth 3
(defskeleton protocol1Intercept
    (vars (a b as name) (nonceB text))
    (defstrand server 3 (a a) (as as) (b b) (nonceB nonceB))
    (non-orig (ltk a as) (ltk b as))
    (uniq-orig nonceB)
)

;;Intruder skeleton
;;Depth 3
(defskeleton protocol1Intercept
    (vars (a b name))
    (defstrand intruder 3 (a a) (b b))
)