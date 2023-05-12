<?php


namespace Drupal\miniorange_saml;

use DOMElement;
use Symfony\Component\HttpFoundation\RedirectResponse;
class MiniOrangeAuthnRequest
{
    public function initiateLogin($zG, $Zq, $YM, $Pu, $qr, $kB, $Nu, $c3)
    {
        $PA = Utilities::createAuthnRequest($zG, $YM, $qr, $Zq, $kB, "\146\141\154\163\x65");
        $this->sendSamlRequestByBindingType($PA, $kB, $Pu, $Zq, $Nu, $c3);
    }
    function sendSamlRequestByBindingType($Dd, $kB, $Nd, $S1, $Nu, $c3)
    {
        if (empty($kB) || $kB == "\110\124\124\x50\55\122\145\144\151\x72\x65\x63\164") {
            goto SD;
        }
        if ($Nu) {
            goto vL;
        }
        $NG = base64_encode($Dd);
        Utilities::postSAMLRequest($S1, $NG, $Nd);
        exit;
        vL:
        $NG = Utilities::signXML($Dd, Utilities::getPublicCertificate(), Utilities::getPrivateKey(), $c3, "\116\x61\x6d\x65\x49\104\120\x6f\154\151\x63\171");
        Utilities::postSAMLRequest($S1, $NG, $Nd);
        goto uI;
        SD:
        $kR = $S1;
        if (strpos($S1, "\x3f") !== false) {
            goto iB;
        }
        $kR .= "\77";
        goto Xy;
        iB:
        $kR .= "\x26";
        Xy:
        $Dd = "\x53\x41\x4d\x4c\x52\145\x71\165\x65\x73\x74\x3d" . $Dd . "\46\122\x65\x6c\141\x79\x53\164\141\164\145\x3d" . urlencode($Nd);
        if (!$Nu) {
            goto JW;
        }
        $mD = array("\164\x79\x70\x65" => "\160\x72\x69\x76\x61\164\x65");
        if ($c3 == "\x52\x53\101\x5f\123\x48\x41\x32\65\66") {
            goto LM;
        }
        if ($c3 == "\122\123\101\137\123\x48\101\x33\x38\64") {
            goto Zf;
        }
        if ($c3 == "\122\x53\x41\137\x53\110\x41\65\x31\x32") {
            goto HW;
        }
        if ($c3 == "\x52\x53\x41\137\x53\110\101\x31") {
            goto lN;
        }
        goto un;
        LM:
        $Dd .= "\46\123\151\147\101\154\x67\x3d" . urlencode(XMLSecurityKey::RSA_SHA256);
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $mD);
        goto un;
        Zf:
        $Dd .= "\x26\123\x69\x67\x41\x6c\x67\75" . urlencode(XMLSecurityKey::RSA_SHA384);
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA384, $mD);
        goto un;
        HW:
        $Dd .= "\46\123\151\x67\101\154\147\x3d" . urlencode(XMLSecurityKey::RSA_SHA512);
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, $mD);
        goto un;
        lN:
        $Dd .= "\x26\123\x69\147\101\x6c\147\x3d" . urlencode(XMLSecurityKey::RSA_SHA1);
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, $mD);
        un:
        $eQ->loadKey(Utilities::getPrivateKey(), FALSE);
        $fx = new XMLSecurityDSig();
        $Tm = $eQ->signData($Dd);
        $Tm = base64_encode($Tm);
        $Dd .= "\x26\x53\x69\147\156\x61\164\165\162\145\75" . urlencode($Tm);
        JW:
        $kR .= $Dd;
        $DI = new RedirectResponse($kR);
        $DI->send();
        uI:
    }
}
