Implementation in Java of the DSA as defined in the FIPS standard


Le programme permet de signer n’impoorte quel type de fichier, le fichier contenant la signature consiste en un fichier contenant les prametres p, q, g, la clé publique du signataire, s et r dans l’ordre ci-mentionné et tous separés par exactement un caractere « passage à la ligne » (toute ces valeurs sont ecrites en base hexadecimale et sans espace dans cette écriture).

pour signer :

java DSA -s NomDuFichierASigner NomVouluPourLeFichierContenantLaSignature [ -k NomDuFichierContenantLaClePrivée ]

java DSA -s NomDuFichierASigner NomVouluPourLeFichierContenantLaSignature [ -c NomDuFichierContenantLesParametres ]

java DSA -s NomDuFichierASigner NomVouluPourLeFichierContenantLaSignature  -k NomDuFichierContenantLaClePrivée 

Les parametres p,q et g par défaut sont les parametres: 
q=2^160+7
p=q* (2^864 +218) + 1
g=2^((p-1)/q) mod p

pour verifier une signature :

java DSA -v NomDuFichierAuthentifier NomDuFichierContenantSaSignature



