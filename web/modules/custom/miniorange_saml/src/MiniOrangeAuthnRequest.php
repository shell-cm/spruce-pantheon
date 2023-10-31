<?php


namespace Drupal\miniorange_saml;

use DOMElement;
use Symfony\Component\HttpFoundation\RedirectResponse;
class MiniOrangeAuthnRequest
{
    public function initiateLogin($se, $WI, $Ot, $Qd, $wi, $xr, $Bw, $dQ)
    {
        $ow = Utilities::createAuthnRequest($se, $Ot, $wi, $WI, $xr, "\146\x61\x6c\163\x65");
        $this->sendSamlRequestByBindingType($ow, $xr, $Qd, $WI, $Bw, $dQ);
    }
    function sendSamlRequestByBindingType($Mm, $xr, $WY, $yr, $Bw, $dQ)
    {
        if (empty($xr) || $xr == "\110\124\x54\x50\x2d\122\x65\x64\x69\x72\145\x63\x74") {
            goto qN;
        }
        if ($Bw) {
            goto JQ;
        }
        $ld = base64_encode($Mm);
        Utilities::postSAMLRequest($yr, $ld, $WY);
        exit;
        JQ:
        $ld = Utilities::signXML($Mm, Utilities::getPublicCertificate(), Utilities::getPrivateKey(), $dQ, "\x4e\x61\155\145\x49\104\120\x6f\x6c\151\143\171");
        Utilities::postSAMLRequest($yr, $ld, $WY);
        goto GV;
        qN:
        $kX = $yr;
        if (strpos($yr, "\77") !== false) {
            goto DD;
        }
        $kX .= "\77";
        goto HL;
        DD:
        $kX .= "\46";
        HL:
        $Mm = "\123\x41\115\x4c\x52\x65\161\165\145\163\164\75" . $Mm . "\x26\x52\x65\154\x61\x79\x53\164\x61\x74\x65\x3d" . urlencode($WY);
        if (!$Bw) {
            goto XE;
        }
        $RO = array("\164\171\160\145" => "\160\162\x69\166\x61\x74\145");
        if ($dQ == "\x52\x53\x41\137\x53\x48\x41\62\x35\66") {
            goto SR;
        }
        if ($dQ == "\122\x53\x41\x5f\123\x48\x41\63\x38\x34") {
            goto Y5;
        }
        if ($dQ == "\x52\123\101\x5f\123\x48\x41\65\x31\62") {
            goto AC;
        }
        if ($dQ == "\x52\x53\x41\137\123\110\101\x31") {
            goto UN;
        }
        goto X7;
        SR:
        $Mm .= "\x26\x53\x69\x67\101\x6c\x67\x3d" . urlencode(XMLSecurityKey::RSA_SHA256);
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $RO);
        goto X7;
        Y5:
        $Mm .= "\46\123\x69\147\101\154\x67\x3d" . urlencode(XMLSecurityKey::RSA_SHA384);
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA384, $RO);
        goto X7;
        AC:
        $Mm .= "\x26\x53\x69\147\x41\x6c\x67\75" . urlencode(XMLSecurityKey::RSA_SHA512);
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, $RO);
        goto X7;
        UN:
        $Mm .= "\x26\x53\151\147\x41\154\x67\x3d" . urlencode(XMLSecurityKey::RSA_SHA1);
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, $RO);
        X7:
        $yQ->loadKey(Utilities::getPrivateKey(), FALSE);
        $d0 = new XMLSecurityDSig();
        $Qz = $yQ->signData($Mm);
        $Qz = base64_encode($Qz);
        $Mm .= "\x26\x53\151\x67\x6e\141\x74\x75\162\145\75" . urlencode($Qz);
        XE:
        $kX .= $Mm;
        $Yq = new RedirectResponse($kX);
        $Yq->send();
        GV:
    }
}
