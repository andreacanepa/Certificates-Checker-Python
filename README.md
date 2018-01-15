# Certificates_Signature_Checking

Code and report provided for the fourth assignment in the "Security" course taken in the MSc in Computer Science and Engineering at Università degli Studi di Genova.

You can find the text of the assignment in "lab_x509_certificates.txt".

Here you can find Python program that takes, as command-line arguments, a sequences of filenames containing PEM encoded certificates, and:
1) print a summary of each certificate (in particular, its: Issuer, Subject, Validity and whether the corresponding key can be used to sign other certificates)
2) check their signatures

In this code, the input directory path is set into the "Run Configuration" settings in Eclipse.
