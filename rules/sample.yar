rule EICAR_Test_Signature {
    meta:
        description = "Detecta la cadena estandar de prueba EICAR"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
