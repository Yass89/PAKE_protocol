This project is done by : Nour El Houda GALAI, Shaina MUMBUKU BAKILI et Yassine BAKRIM.

It implements an Oblivious Pseudo-Random Function (OPRF) protocol to securely perform password-based authentication without exposing the password or derived keys to the opposing party as a plaintext.
The implementation is splited into two phases : Registration, and Login 

# OPRF Phase :
 The OPRF protocol is an interactive protocol executed between a client and a server to compute the output of a pseudo-random function where the server learns nothing about the client's input, and the client learns only the output.
    As shown in the image below, the client initiates the protocol by preparing the password as H(P), where H is a cryptographic hash function and P is the password. The client then generates a random scalar r and computes C = H(P)^r. The value C is sent to the server as the OPRF request.
    Upon receiving C, the server retrieves its secret scalar s and computes R = C^s that will be sent back to the client as the OPRF response.
    The client after receiving R, computes z = r^(-1) and finalizes the OPRF to K = R^z. This results in K being equal to H(P)^s, the client's password hashed and exponentiated with the server's secret without the server ever learning the actual password P, and the client only learns the final output K.


