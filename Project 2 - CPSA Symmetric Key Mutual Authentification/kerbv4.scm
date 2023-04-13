(herald "Kerberos Version 4")

(defprotocol kerb basic
  (defrole authserv
    (vars (c tgs as name) (l text) (K_ctgs skey))
    (trace
     (recv (cat c tgs))
     (send (enc K_ctgs tgs l (enc c tgs K_ctgs (ltk as tgs)) (ltk as c))) ;; (ltk as c) represents the password
     ) 
    (uniq-orig K_ctgs) ;; Server is trusted to always provide a fresh key, that is why this assumption is in the role.
    )
  (defrole ticketserv
    (vars (c tgs as s name) (K_ctgs K_cs skey))
    (trace
     (recv (cat s (enc c tgs K_ctgs (ltk as tgs)) (enc c K_ctgs)))
     (send (enc K_cs s (enc c s K_cs (ltk tgs s)) K_ctgs))
     )
    (uniq-orig K_cs) ;; Server is trusted to always provide a fresh key, that is why this assumption is in the role.
    )
  (defrole server
    (vars (c tgs s name) (time data) (K_cs skey))
    (trace
     (recv (cat (enc c time K_cs) (enc c s K_cs (ltk tgs s))))
     (send (enc (hash time) K_cs)) ;; in Kerberos, the server sends back the encryption of the timestamp-1.
     )  ;; CPSA cannot do arithematic so hash was used instead to transform the timestamp in a way recognizable by both parties.
    )
  (defrole client
    (vars (c as tgs s name) (K_ctgs K_cs skey) (l text) (time data) (tkt_tgs tkt_s mesg))
    (trace
     (send (cat c tgs))
     (recv (enc K_ctgs tgs l tkt_tgs (ltk as c)))
     (send (cat s tkt_tgs (enc c K_ctgs)))
     (recv (enc K_cs s tkt_s K_ctgs))
     (send (cat (enc c time K_cs) tkt_s))
     (recv (enc (hash time) K_cs))
     )
    )
  )

(defskeleton kerb  ;; Check of client authenticating server
  (vars (s tgs c as name))
  (defstrand client 6 (c c) (as as) (tgs tgs) (s s))
  (non-orig (ltk tgs s) (ltk as c) (ltk as tgs))
  )

(defskeleton kerb  ;; Check of server authenticating client
  (vars (s tgs c name))
  (defstrand server 2 (s s) (c c) (tgs tgs))
  (non-orig (ltk tgs s)) ;; Server role does not know about the as, so it can't make any statements about the keys the as shares.
  )

(defprotocol kerb1 basic
  (defrole authserv
    (vars (c tgs as name) (l text) (K_ctgs skey))
    (trace
     (recv (cat c tgs))
     (send (enc K_ctgs tgs l (enc c tgs K_ctgs (ltk as tgs)) (ltk as c)))
     )
    (uniq-orig K_ctgs)
    (non-orig (ltk as c)) ;; added to allow server to know that keys are secure. Generally too restrictive, but in this case the only
    ;; way to allow the server to authenticate the client since the server does not know about the as.
    )
  (defrole ticketserv
    (vars (c tgs as s name) (K_ctgs K_cs skey))
    (trace
     (recv (cat s (enc c tgs K_ctgs (ltk as tgs)) (enc c K_ctgs)))
     (send (enc K_cs s (enc c s K_cs (ltk tgs s)) K_ctgs))
     )
    (uniq-orig K_cs)
    (non-orig (ltk as tgs)) ;; added to allow server to know that keys are secure. Generally too restrictive, but in this case the only
    ;; way to allow the server to authenticate the client since the server does not know about the as.
    )
  (defrole server
    (vars (c tgs s name) (time data) (K_cs skey))
    (trace
     (recv (cat (enc c time K_cs) (enc c s K_cs (ltk tgs s))))
     (send (enc (hash time) K_cs))
     )
    )
  (defrole client
    (vars (c as tgs s name) (K_ctgs K_cs skey) (time data) (l text) (tkt_tgs tkt_s mesg))
    (trace
     (send (cat c tgs))
     (recv (enc K_ctgs tgs l tkt_tgs (ltk as c)))
     (send (cat s tkt_tgs (enc c K_ctgs)))
     (recv (enc K_cs s tkt_s K_ctgs))
     (send (cat (enc c time K_cs) tkt_s))
     (recv (enc (hash time) K_cs))
     )
    )
  )

(defskeleton kerb2
  (vars (s tgs c name))
  (defstrand server 2 (s s) (c c) (tgs tgs))
  (non-orig (ltk tgs s))
  )