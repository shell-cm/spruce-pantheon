<?php


namespace Drupal\miniorange_saml\Controller;

use Drupal\Core\Field\EntityReferenceFieldItemList;
use Drupal\miniorange_saml\HigherUtilities;
use Drupal\profile\Entity\Profile;
use Drupal\taxonomy\Entity\Term;
use Drupal\user\Entity\User;
use Drupal\Component\Utility\Xss;
use Drupal\Core\Form\FormBuilder;
use Drupal\Core\Ajax\AjaxResponse;
use Drupal\miniorange_saml\Utilities;
use Drupal\miniorange_saml\MiniOrangeAcs;
use Drupal\miniorange_saml\AESEncryption;
use Drupal\Core\Controller\ControllerBase;
use Drupal\miniorange_saml\XMLSecurityKey;
use Drupal\miniorange_saml\XMLSecurityDSig;
use Drupal\Core\Ajax\OpenModalDialogCommand;
use Drupal\views\Controller\ViewAjaxController;
use Drupal\views\Plugin\views\area\Entity;
use Symfony\Component\HttpFoundation\Response;
use Drupal\miniorange_saml\MiniOrangeAuthnRequest;
use Drupal\miniorange_saml\MiniorangeSAMLCustomer;
use Drupal\miniorange_saml\MiniorangeSAMLConstants;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\DependencyInjection\ContainerInterface;
class miniorange_samlController extends ControllerBase
{
    protected $formBuilder;
    public function __construct(FormBuilder $Hb)
    {
        $this->formBuilder = $Hb;
    }
    public static function saml_login($Pu = '', $mH = '')
    {
        $y8 = \Drupal::config("\155\151\156\151\x6f\x72\x61\156\x67\145\137\x73\141\155\x6c\x2e\163\x65\x74\164\151\156\147\163");
        if (!(!$y8->get("\155\151\156\151\157\x72\141\156\x67\145\x5f\163\x61\x6d\154\137\145\156\x61\x62\x6c\145\137\x6c\x6f\147\x69\x6e") && strcasecmp($mH, "\164\x65\163\164\x56\x61\x6c\x69\144\x61\x74\145") != 0)) {
            goto bL;
        }
        $jg = "\x43\141\156\x20\x6e\x6f\164\40\151\156\151\164\151\141\164\145\x20\123\123\x4f\56";
        $Dk = '';
        $c8 = "\123\123\x4f\x20\x69\163\40\156\157\164\40\145\156\x61\142\x6c\x65\x64\56";
        Utilities::showErrorMessage($jg, $Dk, $c8, TRUE);
        return new Response();
        bL:
        \Drupal::service("\x70\141\147\145\137\143\141\143\x68\145\137\153\151\x6c\x6c\x5f\x73\167\x69\x74\x63\x68")->trigger();
        $xP = $y8->get("\155\151\x6e\x69\157\162\x61\x6e\147\145\137\x73\141\155\154\137\144\145\146\141\x75\154\x74\137\162\x65\154\141\x79\x73\164\x61\x74\x65");
        $ZC = $y8->get("\x6d\151\x6e\x69\157\162\141\x6e\x67\x65\137\x73\141\155\x6c\x5f\162\145\x71\165\x65\163\164\137\x73\151\147\156\x65\144");
        $c3 = $y8->get("\x73\x65\x63\165\x72\151\x74\x79\x5f\163\x69\147\156\x61\x74\165\162\145\x5f\x61\154\x67\157\x72\151\x74\x68\x6d");
        $eu = $y8->get("\155\x69\156\x69\157\162\x61\156\x67\x65\137\x73\141\x6d\154\137\x68\x74\164\x70\x5f\x62\x69\156\144\x69\156\147");
        $UL = isset($_REQUEST["\144\145\x73\164\x69\156\141\x74\x69\157\x6e"]) ? trim($_REQUEST["\x64\x65\x73\x74\151\156\141\x74\151\157\x6e"], "\x27") : '';
        if (empty($mH)) {
            goto P4;
        }
        $UL = $mH;
        P4:
        if (!empty($UL)) {
            goto Is;
        }
        $UL = $xP;
        Is:
        if (!empty($UL)) {
            goto L6;
        }
        $UL = $Pu;
        L6:
        if (!(empty($UL) && isset($_SERVER["\110\x54\124\x50\137\122\105\x46\x45\122\105\122"]))) {
            goto TP;
        }
        $UL = $_SERVER["\x48\124\124\120\137\122\x45\x46\105\x52\105\x52"];
        TP:
        if (!empty($UL)) {
            goto TH;
        }
        $UL = Utilities::getBaseUrl();
        TH:
        $zG = Utilities::getAcsUrl();
        $Zq = $y8->get("\155\151\x6e\x69\x6f\x72\141\156\147\x65\x5f\x73\x61\155\154\137\151\x64\160\x5f\154\x6f\147\x69\x6e\137\165\162\x6c");
        $qr = $y8->get("\x6d\x69\x6e\x69\x6f\x72\141\x6e\147\145\x5f\x73\141\x6d\154\137\156\141\x6d\145\151\144\x5f\146\157\x72\x6d\141\x74");
        $hj = new MiniOrangeAuthnRequest();
        $hj->initiateLogin($zG, $Zq, Utilities::getIssuer(), $UL, $qr, $eu, $ZC, $c3);
        return new Response();
    }
    public static function create(ContainerInterface $w6)
    {
        return new static($w6->get("\146\157\162\155\x5f\x62\165\151\x6c\x64\145\162"));
    }
    public function saml_response()
    {
        global $base_url;
        global $sR;
        if (isset($_GET["\x53\x41\x4d\x4c\122\145\x73\x70\x6f\156\x73\x65"])) {
            goto DV;
        }
        $y8 = \Drupal::config("\x6d\x69\156\x69\x6f\x72\x61\x6e\147\x65\137\x73\141\155\x6c\x2e\x73\145\164\164\x69\156\x67\x73");
        $Bj = (array) json_decode($y8->get("\x6d\151\156\151\157\162\x61\x6e\147\x65\x5f\x73\x61\155\154\x5f\x63\165\x73\164\157\155\x5f\141\164\164\x72\163\137\x6d\141\x70\137\x61\x72\162"));
        $Ab = new MiniOrangeAcs();
        $fv = $y8->get("\155\x69\x6e\157\x72\x61\156\147\x65\x5f\163\141\155\154\137\x63\x75\x73\x74\157\155\x65\162\137\x61\144\155\x69\156\137\x66\x72\x61\x75\x64\137\143\150\145\143\153");
        $Yx = $y8->get("\155\x69\156\x69\x6f\x72\141\x6e\147\145\x5f\x73\x61\x6d\154\137\143\165\163\164\157\155\x65\x72\137\x61\144\x6d\151\156\x5f\164\157\153\x65\156");
        $Kj = $y8->get("\155\x69\156\x69\157\x72\x61\156\x67\145\x5f\x73\141\155\154\137\x63\165\163\x74\157\155\145\162\x5f\141\144\155\151\x6e\x5f\145\x6d\x61\151\154");
        $Ym = \Drupal::request()->server->get("\104\117\x43\125\x4d\105\x4e\124\x5f\x52\117\117\124") . $sR;
        $al = trim($base_url, "\57");
        if (preg_match("\x23\x5e\150\x74\x74\x70\50\x73\51\x3f\72\57\x2f\x23", $al)) {
            goto XD;
        }
        $al = "\x68\x74\164\160\72\57\57" . $al;
        XD:
        $qz = parse_url($al);
        $ka = isset($qz["\160\141\x74\150"]) ? $qz["\160\x61\x74\x68"] : '';
        $Sl = preg_replace("\57\136\167\167\x77\x5c\56\x2f", '', $qz["\x68\x6f\163\164"] . $ka);
        $mR = $Ym . $Sl;
        $Zc = $y8->get("\x6d\151\156\x69\x6f\x72\x61\156\x67\x65\x5f\x73\141\x6d\154\x5f\151\x73\x4d\x75\154\164\x69\123\x69\164\x65\x50\x6c\x75\147\151\x6e\122\145\x71\165\x65\x73\x74\x65\x64") == true;
        if (($Zc || $mR == AESEncryption::decrypt_data($fv, $Yx) || $mR == AESEncryption::decrypt_data($fv, $Yx, "\x41\105\x53\x2d\61\x32\70\x2d\x45\x43\x42")) && $Kj != null && $Kj != '') {
            goto YS;
        }
        if ($Kj != null && $Kj != '') {
            goto eU;
        }
        if (!($Kj == null || $Kj == '')) {
            goto xy;
        }
        $jg = "\x59\x6f\x75\x20\x61\x72\145\x20\156\157\x74\40\154\157\147\147\145\x64\x20\x69\x6e\56";
        $Dk = "\120\x6c\x65\x61\x73\145\x20\x6c\x6f\147\151\156\40\146\x69\162\x73\164\x20\164\157\40\141\143\x74\151\x76\141\x74\x65\x20\163\x69\156\x67\154\145\40\163\151\x67\156\x20\x6f\x6e\x2e";
        $c8 = "\115\x61\153\145\40\x73\x75\162\145\40\171\x6f\165\40\x68\141\166\x65\40\x6c\x6f\147\147\145\144\x20\151\156\x2f\40\122\x65\147\151\x73\164\x65\162\x20\x69\x6e\40\x74\x6f\40\155\x6f\x64\x75\154\145\x2e";
        Utilities::showErrorMessage($jg, $Dk, $c8);
        xy:
        goto Fa;
        eU:
        if (isset($_POST["\x52\145\154\x61\x79\x53\164\141\164\145"]) && $_POST["\122\145\x6c\141\171\123\x74\141\164\x65"] == "\x74\x65\x73\x74\x56\141\x6c\x69\144\x61\164\145") {
            goto NH;
        }
        $jg = "\127\x65\x20\143\157\165\154\144\40\x6e\x6f\164\40\x73\x69\147\156\40\x79\157\x75\40\151\x6e\x2e";
        $Dk = "\x50\154\145\x61\x73\x65\x20\103\x6f\x6e\x74\141\143\x74\40\171\157\x75\162\x20\x61\x64\x6d\x69\156\x69\163\x74\x72\141\164\157\x72\x2e";
        Utilities::showErrorMessage($jg, $Dk, "\x2d");
        goto M5;
        NH:
        $jg = "\114\x69\x63\145\156\x73\x65\x20\153\x65\171\x20\171\x6f\165\40\x68\x61\166\145\40\145\x6e\164\x65\162\x65\x64\40\x68\141\x73\x20\x61\x6c\162\x65\141\144\171\40\142\x65\145\x6e\40\165\x73\x65\x64\56";
        $Dk = "\120\x6c\145\x61\163\x65\x20\145\x6e\164\145\162\40\141\x20\153\145\x79\40\x77\150\x69\x63\x68\40\x68\x61\x73\40\x6e\157\164\x20\142\x65\145\156\40\x75\x73\145\x64\40\x62\145\x66\157\162\x65\40\x6f\156\40\x61\x6e\171\x20\157\x74\150\145\162\40\x69\x6e\163\164\x61\x6e\x63\x65\x20\157\x72\40\151\146\40\171\157\165\x20\150\x61\x76\145\40\145\170\x61\165\163\x74\x65\x64\40\x61\x6c\154\40\x79\x6f\x75\162\40\x6b\145\x79\x73\40\164\x68\x65\156\x20\142\165\x79\x20\x6d\x6f\x72\x65\x20\154\151\143\145\156\163\x65\40\x66\162\x6f\x6d\40\x4c\151\143\x65\156\x73\151\x6e\x67\x2e";
        Utilities::showErrorMessage($jg, $Dk, "\x2d");
        M5:
        Fa:
        goto EB;
        YS:
        \Drupal::moduleHandler()->invokeAll("\146\157\x72\x77\x61\x72\144\x5f\x72\x65\163\160\157\x6e\x73\145", [$_POST]);
        $Xe = $Ab->processSamlResponse($_POST, $Bj);
        $DI = $Xe["\162\x65\163\160\157\x6e\x73\145"];
        $Eh = $Xe["\162\145\x73\157\165\x72\143\x65\163"];
        EB:
        if (!(MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION && \Drupal\miniorange_saml\HigherUtilities::Is_Restricted_Domain($DI["\x65\155\141\151\154"]) === TRUE)) {
            goto Hf;
        }
        $jg = "\131\157\165\40\141\x72\x65\x20\156\x6f\164\x20\141\x6c\154\x6f\x77\x65\144\x20\164\x6f\40\154\x6f\147\x69\156\40";
        $Dk = "\x50\x6c\145\141\x73\145\40\x43\x6f\156\x74\141\x63\164\x20\x79\x6f\165\x72\40\141\x64\155\151\156\x69\163\x74\162\x61\164\157\x72\x2e";
        $c8 = "\131\x6f\x75\x72\40\x64\157\155\x61\x69\156\40\155\141\x79\x20\x62\145\x20\142\154\x6f\x63\x6b\x65\x64\40\142\171\x20\141\144\155\151\x6e";
        Utilities::showErrorMessage($jg, $Dk, $c8);
        Hf:
        if ($y8->get("\155\x69\156\151\x6f\162\141\156\x67\145\x5f\163\x61\155\154\137\154\157\x61\x64\137\165\163\x65\162") == 1) {
            goto G2;
        }
        $vw = user_load_by_name($DI["\x75\163\x65\162\x6e\141\x6d\x65"]);
        goto XO;
        G2:
        $vw = user_load_by_mail($DI["\145\x6d\141\x69\x6c"]);
        XO:
        $uB = 0;
        if (!($vw == NULL)) {
            goto Lp;
        }
        $Rh = $y8->get("\x6d\151\156\151\157\162\x61\156\x67\145\x5f\x73\x61\155\x6c\137\144\151\163\141\x62\x6c\x65\137\141\165\x74\157\143\x72\x65\141\x74\x65\x5f\x75\x73\x65\162\x73");
        if ($Rh) {
            goto Ay;
        }
        $kw = user_password(8);
        $Bk = $y8->get("\155\x69\x6e\x69\157\162\141\x6e\x67\x65\137\x73\x61\155\154\x5f\144\x65\146\x61\x75\x6c\164\137\x72\157\x6c\x65");
        $Nb = ["\156\x61\155\145" => $DI["\165\163\145\162\x6e\141\x6d\145"], "\155\x61\151\154" => $DI["\x65\x6d\141\x69\x6c"], "\x70\141\x73\x73" => $kw, "\x73\x74\141\164\165\x73" => 1];
        $vw = User::create($Nb);
        $vw->save();
        if (!($Bk != "\x61\165\164\x68\x65\156\x74\151\143\x61\164\145\x64" && $y8->get("\155\x69\156\x69\157\162\141\x6e\x67\145\137\x73\141\155\x6c\137\145\156\x61\x62\154\145\137\x72\157\154\x65\x6d\141\160\160\x69\x6e\x67"))) {
            goto af;
        }
        $vw->addRole($Bk);
        $vw->save();
        af:
        goto Gb;
        Ay:
        $jg = "\101\x63\x63\x6f\x75\156\x74\40\144\157\x65\163\x20\156\157\x74\40\145\170\151\x73\x74\40\167\151\164\x68\x20\x79\x6f\x75\x72\x20\165\x73\145\162\156\x61\155\x65\x2e";
        $Dk = "\x50\x6c\x65\x61\x73\145\x20\103\157\156\164\141\x63\x74\x20\171\x6f\165\x72\40\x61\x64\155\151\x6e\151\163\164\162\141\164\x6f\162\x2e";
        $c8 = "\x41\165\164\x6f\x20\143\x72\x65\x61\x74\x69\157\x6e\x20\157\x66\40\x75\x73\x65\x72\x20\151\163\x20\156\157\x74\40\141\154\154\x6f\x77\145\x64\40\x69\x66\40\x75\x73\x65\x72\40\x64\157\x65\x73\x20\156\x6f\164\x20\145\x78\151\x73\164\x2e";
        Utilities::showErrorMessage($jg, $Dk, $c8);
        Gb:
        Lp:
        $FE = array();
        $FE = $DI["\x63\165\163\164\157\x6d\x46\151\x65\154\144\x41\164\164\x72\x69\142\x75\x74\x65\163"];
        $vw = User::load($vw->id());
        $wh = json_decode($y8->get("\155\151\x6e\x69\x6f\x72\141\x6e\147\145\x5f\163\141\155\x6c\x5f\x63\165\163\164\x6f\155\137\141\x74\164\162\x73\137\155\x61\160\137\163\145\160"));
        foreach ($FE as $eQ => $yX) {
            $IU = $vw->get($eQ);
            $wI = $IU->getFieldDefinition();
            $Sj = $wI->getFieldStorageDefinition();
            if ($Sj->getType() === "\145\156\x74\x69\x74\171\137\162\x65\x66\x65\162\x65\x6e\x63\x65") {
                goto QA;
            }
            if (Utilities::isMultiple($eQ) && !is_null($wh->{$eQ})) {
                goto YL;
            }
            $LN = array($yX);
            goto cP;
            YL:
            $LN = explode($wh->{$eQ}, $yX);
            cP:
            $vw->get($eQ)->setValue($LN);
            $vw->save();
            goto FG;
            QA:
            $RJ = $Sj->getSetting("\164\x61\162\147\x65\164\137\164\x79\160\x65");
            $z9 = $wI->getSetting("\150\x61\x6e\x64\154\145\x72\137\x73\x65\164\x74\x69\156\x67\163");
            $mq = \Drupal::entityTypeManager()->getStorage($RJ)->loadMultiple(NULL);
            if (!isset($z9["\164\x61\162\x67\x65\x74\x5f\142\x75\156\x64\154\x65\x73"])) {
                goto ZT;
            }
            if (Utilities::isMultiple($eQ) && !is_null($wh->{$eQ})) {
                goto Q4;
            }
            $LN = array($yX);
            goto KE;
            Q4:
            $LN = explode($wh->{$eQ}, $yX);
            KE:
            $Tq = [];
            $Ak = [];
            foreach ($LN as $yX) {
                $mq = \Drupal::entityTypeManager()->getStorage($RJ)->loadByProperties(["\x6e\x61\x6d\145" => $yX]);
                $m6 = false;
                foreach ($mq as $la) {
                    if (!in_array($la->bundle(), $z9["\164\141\162\147\145\x74\137\x62\x75\156\x64\154\145\163"])) {
                        goto Hn;
                    }
                    $Tq[] = $la->id();
                    $m6 = true;
                    Hn:
                    kD:
                }
                iv:
                if ($m6) {
                    goto YI;
                }
                $Ak[] = $yX;
                YI:
                ST:
            }
            gm:
            $N8 = isset($z9["\141\x75\164\157\x5f\x63\162\145\x61\164\x65"]) ? $z9["\x61\165\x74\157\x5f\143\162\x65\x61\164\x65"] : false;
            $Km = isset($z9["\141\x75\x74\x6f\137\x63\x72\145\x61\164\x65\x5f\142\x75\x6e\144\154\145"]) ? $z9["\x61\x75\x74\157\137\x63\162\145\141\x74\x65\x5f\142\x75\156\144\x6c\145"] : '';
            if (!($N8 && $RJ == "\x74\x61\x78\x6f\x6e\157\x6d\x79\137\x74\145\162\x6d")) {
                goto nK;
            }
            foreach ($Ak as $MF) {
                $F9 = Term::create(["\x6e\x61\x6d\145" => $MF, "\x76\151\x64" => $Km]);
                $F9->save();
                $Tq[] = $F9->id();
                j6:
            }
            ib:
            nK:
            $IU->setValue($Tq);
            $vw->save();
            ZT:
            FG:
            ht:
        }
        CU:
        if (!(!is_null($vw) && $y8->get("\x6d\151\156\x69\157\162\141\156\x67\145\x5f\x73\x61\x6d\x6c\137\145\x6e\141\x62\x6c\145\x5f\162\157\x6c\145\x6d\x61\x70\160\151\x6e\147"))) {
            goto qO;
        }
        $Uj = $y8->get("\x6d\x69\x6e\x69\157\162\141\156\147\145\137\x73\141\x6d\x6c\x5f\x72\x6f\x6c\x65\137\155\141\x70\160\x69\x6e\147\x5f\x61\x72\x72") != null ? (array) json_decode($y8->get("\x6d\x69\x6e\151\157\x72\x61\156\x67\145\137\163\x61\x6d\154\137\x72\157\x6c\145\x5f\155\141\160\x70\x69\156\x67\x5f\141\162\x72")) : [];
        $jU = array();
        $jU = $DI["\x63\x75\163\164\157\155\x46\151\145\x6c\x64\122\x6f\154\145\163"];
        $lx = \Drupal::configFactory()->getEditable("\155\151\x6e\151\x6f\162\141\156\x67\x65\137\163\141\x6d\154\x2e\x73\x65\x74\x74\x69\x6e\147\163")->get("\x6d\151\156\x69\157\162\x61\156\x67\145\137\163\141\155\x6c\x5f\144\151\163\141\142\x6c\145\137\x72\x6f\154\x65\137\165\x70\x64\141\164\145");
        $lb = $vw->getRoles();
        if ($lx) {
            goto m3;
        }
        foreach ($lb as $eQ => $yX) {
            if (in_array($yX, array_keys($Uj))) {
                goto EW;
            }
            if (!($yX != $y8->get("\155\x69\x6e\151\x6f\162\x61\x6e\147\145\x5f\x73\141\155\154\x5f\144\x65\x66\x61\x75\x6c\x74\137\162\x6f\x6c\145"))) {
                goto NU;
            }
            $vw->removeRole($yX);
            $vw->save();
            NU:
            EW:
            ZJ:
        }
        ZN:
        m3:
        foreach ($Uj as $eQ => $yX) {
            $qL = FALSE;
            $Aj = explode("\73", $yX);
            foreach ($Aj as $r2 => $NC) {
                if (!(is_array($jU) && in_array($NC, $jU))) {
                    goto V7;
                }
                $qL = TRUE;
                V7:
                Xu:
            }
            jk:
            if ($qL && $eQ != "\141\165\164\150\x65\156\164\151\143\x61\x74\145\x64") {
                goto Iw;
            }
            $vw->removeRole($eQ);
            $vw->save();
            goto v2;
            Iw:
            $vw->addRole($eQ);
            $vw->save();
            v2:
            Yi:
        }
        VF:
        qO:
        $vk = $y8->get("\x6d\151\x6e\x69\x6f\162\141\x6e\147\x65\137\x73\141\x6d\154\x5f\145\x6e\141\142\154\x65\x5f\x70\x72\157\x66\x69\154\x65\137\x6d\141\160\x70\x69\156\x67");
        if (!(MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION && $vk)) {
            goto aK;
        }
        HigherUtilities::profileFieldMapping($vw, $Eh);
        aK:
        if (user_is_blocked($DI["\x75\163\x65\x72\x6e\x61\155\145"]) == FALSE) {
            goto oH;
        }
        $jg = "\125\x73\145\x72\x20\x42\x6c\157\143\x6b\x65\144\40\102\171\40\x41\x64\155\x69\156\151\x73\164\x72\141\x74\x6f\162\56";
        $Dk = "\x50\x6c\x65\x61\163\145\40\x43\x6f\156\x74\x61\x63\x74\x20\x79\157\165\162\x20\x61\x64\x6d\x69\x6e\151\x73\x74\x72\x61\164\x6f\x72\x2e";
        $c8 = "\x54\x68\x69\x73\x20\x75\163\x65\162\x20\141\143\143\x6f\x75\x6e\164\40\x69\163\x20\x6e\x6f\x74\40\141\x6c\154\x6f\167\x65\x64\40\x74\x6f\x20\154\157\x67\151\156\56";
        Utilities::showErrorMessage($jg, $Dk, $c8);
        return new Response();
        goto oX;
        oH:
        if (!(array_key_exists("\x72\x65\x6c\141\x79\x5f\163\164\141\164\x65", $DI) && !empty($DI["\162\145\154\141\171\x5f\163\x74\x61\x74\x65"]))) {
            goto O0;
        }
        $m0 = $DI["\x72\145\154\x61\x79\x5f\163\x74\x61\x74\x65"];
        O0:
        $ce = Utilities::getBaseUrl();
        if (!(empty($m0) || $m0 == "\x2f")) {
            goto xW;
        }
        $m0 = $ce;
        xW:
        $_SESSION["\163\145\x73\x73\151\x6f\x6e\x49\156\x64\x65\x78"] = $DI["\163\x65\x73\x73\x69\x6f\x6e\111\x6e\x64\x65\170"];
        $_SESSION["\x4e\141\x6d\145\111\x44"] = $DI["\x4e\x61\x6d\x65\x49\x44"];
        $_SESSION["\x6d\x6f\x5f\x73\x61\155\154"]["\x6c\157\x67\x67\145\144\137\x69\x6e\137\x77\x69\164\x68\137\x69\144\160"] = TRUE;
        \Drupal::moduleHandler()->invokeAll("\x69\156\166\157\153\x65\137\155\151\156\x69\157\x72\141\156\x67\x65\137\x32\x66\x61\x5f\142\x65\x66\x6f\162\x65\x5f\154\157\x67\x69\156", [$vw]);
        \Drupal::moduleHandler()->invokeAll("\155\x69\x6e\x69\157\162\141\156\147\x65\137\x73\x61\155\154\x5f\151\144\160\137\162\x65\x73\157\165\162\x63\145\x73", [$vw, $Eh]);
        user_login_finalize($vw);
        if (!($y8->get("\x6d\x69\156\151\157\162\141\x6e\x67\x65\x5f\x73\141\x6d\x6c\x5f\162\145\x73\x74\162\151\143\x74\137\162\145\x64\151\x72\x65\x63\x74\137\x6f\165\x74\x73\x69\x64\x65\137\144\x6f\x6d\x61\151\x6e") == TRUE)) {
            goto cY;
        }
        $MJ = parse_url($m0);
        $ER = parse_url($ce);
        $a0 = isset($ER["\x68\157\163\x74"]) ? $ER["\x68\x6f\x73\164"] : FALSE;
        $Wu = isset($MJ["\150\157\163\164"]) ? $MJ["\150\157\163\164"] : FALSE;
        if (!($Wu !== FALSE && $a0 !== $Wu)) {
            goto yU;
        }
        $II = $m0;
        $m0 = $ce;
        $wU = $y8->get("\155\x69\x6e\x69\x6f\x72\x61\x6e\x67\145\137\163\141\155\x6c\137\167\150\151\x74\x65\x6c\151\x73\x74\137\144\x6f\155\x61\x69\x6e\x73");
        $WG = explode("\73", $wU);
        foreach ($WG as $HQ) {
            if (!($HQ == '' or $HQ == "\57")) {
                goto nm;
            }
            goto rh;
            nm:
            if (!(strpos($Wu, trim($HQ)) !== false)) {
                goto rO;
            }
            $m0 = $II;
            goto RX;
            rO:
            rh:
        }
        RX:
        yU:
        cY:
        $DI = new RedirectResponse($m0);
        $ap = \Drupal::request();
        $ap->getSession()->save();
        $DI->prepare($ap);
        \Drupal::service("\153\x65\x72\156\x65\154")->terminate($ap, $DI);
        $DI->send();
        exit;
        return new Response();
        oX:
        goto bc;
        DV:
        $ap = \Drupal::request();
        $ap->getSession()->clear();
        $DI = new RedirectResponse(Utilities::getBaseUrl());
        $DI->send();
        return new Response();
        bc:
        return new Response();
    }
    static function saml_logout()
    {
        $y8 = \Drupal::config("\155\x69\156\x69\x6f\x72\141\x6e\x67\145\x5f\x73\x61\x6d\x6c\56\x73\145\x74\x74\151\x6e\147\x73");
        $c3 = $y8->get("\163\x65\143\x75\x72\151\164\x79\137\x73\151\x67\x6e\141\164\165\162\x65\137\141\x6c\147\x6f\x72\x69\164\150\155");
        $Xm = Utilities::getBaseUrl();
        $pX = Utilities::getRedirectUrAfterLogout($Xm);
        $JS = $y8->get("\155\151\x6e\151\157\x72\141\x6e\147\x65\137\x73\x61\155\x6c\137\x69\144\x70\x5f\154\157\147\x6f\165\x74\137\x75\x72\154");
        $F3 = $y8->get("\x6d\151\156\x69\x6f\x72\141\156\147\145\137\x73\x61\155\154\137\x73\x6c\157\x5f\x68\x74\x74\x70\137\142\x69\156\144\151\x6e\x67");
        if (!empty($JS)) {
            goto HU;
        }
        $ap = \Drupal::request();
        $ap->getSession()->clear();
        $DI = new RedirectResponse($pX);
        $DI->send();
        return new Response();
        goto Oe;
        HU:
        if (!\Drupal::service("\x73\145\163\x73\151\x6f\x6e")->getId() || \Drupal::service("\163\145\163\x73\151\157\x6e")->getId() == '' || !isset($_SESSION)) {
            goto G3;
        }
        if (!isset($_SESSION["\x6d\157\x5f\x73\x61\155\154"]["\154\157\147\x67\145\x64\x5f\151\x6e\x5f\x77\x69\x74\x68\137\151\x64\160"])) {
            goto ma;
        }
        unset($_SESSION["\x6d\x6f\x5f\x73\141\155\154"]);
        $u8 = $_SESSION["\x73\145\x73\x73\x69\x6f\156\111\x6e\144\145\x78"];
        $Pp = $_SESSION["\116\x61\x6d\x65\x49\x44"];
        Utilities::checkIfLogoutRequest($_REQUEST, $_GET);
        $Nd = $Xm;
        $Dd = Utilities::createLogoutRequest($Pp, Utilities::getIssuer(), $JS, $F3, $u8);
        $ZC = $y8->get("\155\151\156\x69\157\x72\x61\156\147\145\x5f\x73\x61\x6d\x6c\137\162\x65\x71\165\x65\163\x74\x5f\163\151\147\x6e\145\144");
        if (empty($F3) || $F3 == "\110\124\124\120\55\122\x65\x64\x69\x72\x65\x63\x74") {
            goto zY;
        }
        if ($ZC) {
            goto o4;
        }
        $NG = base64_encode($Dd);
        Utilities::postSAMLRequest($JS, $NG, $Nd);
        exit;
        o4:
        $NG = Utilities::signXML($Dd, Utilities::getPublicCertificate(), Utilities::getPrivateKey(), $c3, "\x4e\x61\155\x65\111\x44");
        Utilities::postSAMLRequest($JS, $NG, $Nd);
        goto QU;
        zY:
        $Dd = "\x53\101\x4d\x4c\122\145\161\x75\x65\163\x74\75" . $Dd . "\46\122\x65\154\x61\171\123\x74\141\164\145\x3d" . urlencode($Nd);
        $kR = $JS;
        if (strpos($JS, "\x3f") !== false) {
            goto UL;
        }
        $kR .= "\x3f";
        goto L4;
        UL:
        $kR .= "\x26";
        L4:
        if (!$ZC) {
            goto cz;
        }
        if ($c3 == "\x52\123\101\137\123\110\101\62\65\x36") {
            goto Td;
        }
        if ($c3 == "\122\123\101\137\123\x48\x41\x33\x38\64") {
            goto Au;
        }
        if ($c3 == "\x52\x53\101\x5f\x53\110\x41\x35\x31\62") {
            goto Q9;
        }
        if ($c3 == "\x52\x53\101\137\x53\110\x41\x31") {
            goto aR;
        }
        goto jF;
        Td:
        $Dd .= "\x26\123\151\147\x41\154\147\75" . urlencode(XMLSecurityKey::RSA_SHA256);
        goto jF;
        Au:
        $Dd .= "\x26\x53\151\147\x41\154\147\75" . urlencode(XMLSecurityKey::RSA_SHA384);
        goto jF;
        Q9:
        $Dd .= "\x26\123\151\147\101\154\x67\75" . urlencode(XMLSecurityKey::RSA_SHA512);
        goto jF;
        aR:
        $Dd .= "\x26\x53\x69\x67\x41\154\147\x3d" . urlencode(XMLSecurityKey::RSA_SHA1);
        jF:
        $mD = array("\x74\x79\x70\145" => "\160\x72\151\166\x61\x74\145");
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $mD);
        if ($c3 == "\122\123\101\x5f\x53\x48\x41\63\x38\x34") {
            goto OZ;
        }
        if ($c3 == "\x52\123\x41\137\123\x48\x41\65\61\62") {
            goto jr;
        }
        if ($c3 == "\122\123\101\137\123\x48\101\x31") {
            goto lK;
        }
        goto fK;
        OZ:
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA384, $mD);
        goto fK;
        jr:
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, $mD);
        goto fK;
        lK:
        $eQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, $mD);
        fK:
        $eQ->loadKey(Utilities::getPrivateKey(), FALSE);
        $fx = new XMLSecurityDSig();
        $Tm = $eQ->signData($Dd);
        $Tm = base64_encode($Tm);
        $kR .= $Dd . "\x26\x53\x69\147\156\141\x74\165\162\145\x3d" . urlencode($Tm);
        if ($y8->get("\x6d\151\x6e\x69\157\162\x61\156\147\x65\137\163\141\x6d\x6c\137\163\x65\x6e\144\x5f\163\154\x6f\137\x69\156\137\151\x66\162\x61\x6d\145")) {
            goto yp;
        }
        header("\114\x6f\x63\141\164\x69\x6f\156\72\x20" . $kR);
        exit;
        goto k8;
        yp:
        echo "\x3c\151\x66\162\x61\155\145\x20\151\144\x3d\x27\x6d\157\x5f\x73\141\155\x6c\x5f\x69\146\x72\141\x6d\x65\x5f\163\154\157\x27\x20\x73\162\x63\x3d\x27" . $kR . "\47\40\x73\164\171\154\x65\75\x27\160\157\x73\151\164\x69\x6f\x6e\x3a\40\x61\x62\163\157\154\x75\164\145\73\x20\x68\x65\151\x67\x68\164\x3a\x20\x30\x3b\x20\x77\151\x64\x74\x68\72\40\x30\73\40\x62\157\162\144\145\x72\x3a\x20\60\73\x27\x20\x3e\x3c\x2f\x69\146\162\x61\x6d\x65\76";
        exit;
        k8:
        goto xx;
        cz:
        $kR .= $Dd;
        if ($y8->get("\x6d\151\x6e\x69\x6f\162\x61\156\147\145\x5f\163\x61\155\154\137\x73\145\156\144\137\163\x6c\x6f\137\x69\x6e\x5f\151\146\x72\x61\155\x65")) {
            goto yB;
        }
        $DI = new RedirectResponse($kR);
        $DI->send();
        return new Response();
        goto Hg;
        yB:
        echo "\74\x69\x66\162\x61\x6d\145\40\151\x64\x3d\x27\x6d\x6f\137\x73\141\x6d\x6c\x5f\151\146\x72\141\x6d\145\x5f\163\154\x6f\47\40\x73\162\x63\75\x27" . $kR . "\47\x20\x73\x74\x79\154\145\75\47\x70\157\x73\x69\x74\x69\157\156\72\x20\x61\142\x73\157\x6c\165\164\x65\73\40\150\x65\x69\147\150\164\72\40\x30\x3b\x20\167\151\144\164\150\72\40\x30\x3b\40\142\157\x72\x64\145\162\x3a\40\60\73\x27\40\x3e\x3c\57\151\x66\162\x61\x6d\145\x3e";
        exit;
        Hg:
        xx:
        QU:
        ma:
        $ap = \Drupal::request();
        $ap->getSession()->clear();
        if (!($y8->get("\x6d\151\x6e\151\157\x72\141\x6e\x67\x65\137\163\x61\155\154\137\x73\x65\156\144\137\x73\154\x6f\x5f\x69\156\137\151\x66\x72\141\x6d\145") && !isset($_GET["\146\x69\156\x61\x6c"]))) {
            goto ju;
        }
        echo "\74\x73\x63\x72\x69\x70\164\x3e\x20\x77\x69\x6e\x64\x6f\167\56\164\157\160\56\154\x6f\143\141\x74\151\x6f\x6e\56\150\162\x65\146\x20\75\40\47" . $Xm . "\57\165\163\145\162\57\x6c\x6f\x67\157\165\x74\77\146\x69\156\x61\x6c\x3d\x74\162\x75\145\47\x3b\x20\74\x2f\163\x63\x72\x69\160\164\x3e";
        exit;
        ju:
        $DI = new RedirectResponse($pX);
        $DI->send();
        return new Response();
        goto PJ;
        G3:
        session_start();
        return new Response();
        PJ:
        Oe:
        return new Response();
    }
    function test_configuration()
    {
        self::saml_login('', "\x74\x65\163\x74\126\141\x6c\151\144\x61\x74\145");
        return new Response();
    }
    function saml_request()
    {
        $S1 = \Drupal::config("\155\x69\x6e\x69\157\x72\x61\x6e\147\x65\x5f\163\141\155\154\x2e\x73\145\164\164\151\x6e\x67\163")->get("\155\151\156\x69\x6f\162\141\x6e\147\145\x5f\163\141\x6d\x6c\x5f\151\x64\160\137\x6c\157\x67\151\156\x5f\165\x72\154");
        $qr = \Drupal::config("\x6d\151\156\x69\157\162\x61\156\147\145\x5f\x73\x61\155\x6c\x2e\x73\x65\x74\x74\x69\x6e\x67\x73")->get("\155\151\156\x69\x6f\162\x61\x6e\x67\x65\x5f\163\x61\x6d\x6c\x5f\156\x61\155\145\151\144\137\146\157\162\x6d\141\164");
        $LM = Utilities::createAuthnRequest(Utilities::getAcsUrl(), Utilities::getIssuer(), $qr, $S1, "\x48\x54\x54\x50\x2d\x50\x4f\x53\124", "\x66\141\154\163\x65");
        $Nd = "\144\x69\x73\160\x6c\x61\x79\123\101\x4d\x4c\122\x65\161\x75\145\x73\x74";
        $ZC = \Drupal::config("\x6d\x69\x6e\151\157\x72\x61\156\147\145\137\x73\x61\155\154\x2e\163\x65\164\164\151\156\147\x73")->get("\155\151\156\x69\x6f\162\141\x6e\x67\145\137\x73\141\155\154\x5f\x72\x65\161\165\145\163\164\137\x73\x69\147\x6e\x65\144");
        $c3 = \Drupal::config("\155\151\156\151\157\x72\x61\x6e\x67\x65\x5f\163\141\x6d\154\56\163\x65\x74\x74\151\x6e\147\163")->get("\163\145\x63\165\x72\x69\164\x79\137\163\x69\147\x6e\141\x74\165\162\x65\x5f\x61\x6c\147\157\x72\x69\164\150\155");
        if (!$ZC) {
            goto c3;
        }
        $NG = Utilities::signXML($LM, Utilities::getPublicCertificate(), Utilities::getPrivateKey(), $c3, "\x4e\141\x6d\145\x49\x44\x50\x6f\x6c\151\x63\x79");
        $LM = base64_decode($NG);
        c3:
        Utilities::Print_SAML_Request($LM, $Nd);
        return new Response();
    }
    function saml_response_generator()
    {
        self::saml_login('', "\x64\151\x73\160\154\141\171\123\x61\x6d\154\x52\145\163\160\x6f\x6e\163\145");
        return new Response();
    }
    public function openModalForm()
    {
        $DI = new AjaxResponse();
        $XB = $this->formBuilder->getForm("\x5c\x44\x72\165\160\x61\154\x5c\x6d\151\x6e\x69\x6f\x72\x61\x6e\x67\x65\137\163\x61\155\154\134\x46\157\x72\x6d\134\115\x69\x6e\x69\x6f\162\x61\x6e\147\145\x53\101\x4d\x4c\122\x65\x6d\157\166\x65\114\151\143\x65\156\163\x65");
        $DI->addCommand(new OpenModalDialogCommand("\122\x65\x6d\x6f\166\x65\x20\x4c\x69\x63\x65\x6e\163\x65\40\x4b\145\171", $XB, ["\167\x69\x64\164\150" => "\x38\60\x30"]));
        return $DI;
    }
    public function moLicenseFetch()
    {
        global $base_url;
        $Kj = \Drupal::config("\x6d\151\156\x69\x6f\x72\141\156\x67\x65\x5f\163\x61\x6d\x6c\56\x73\145\x74\x74\151\156\147\163")->get("\155\x69\x6e\151\x6f\162\x61\156\147\x65\x5f\x73\x61\155\154\x5f\x63\x75\x73\x74\157\x6d\x65\x72\x5f\141\144\x6d\151\156\x5f\x65\155\x61\x69\x6c");
        $HC = new MiniorangeSAMLCustomer($Kj, NULL, NULL, NULL);
        $QL = json_decode($HC->ccl(), true);
        Utilities::mo_save_expiry_details($QL);
        \Drupal::messenger()->addStatus(t("\123\165\143\x63\145\x73\163\146\165\x6c\x6c\171\40\x66\145\x74\143\x68\145\144\40\164\x68\145\40\165\x70\x64\x61\164\x65"));
        $DI = new RedirectResponse($base_url . "\x2f\141\x64\155\x69\156\57\143\x6f\156\x66\x69\147\57\x70\145\x6f\160\154\x65\x2f\155\x69\156\x69\157\162\x61\x6e\147\145\137\x73\141\x6d\154\x2f\143\165\x73\164\x6f\155\x65\x72\x5f\163\145\164\165\x70");
        $DI->send();
    }
    function saml_metadata()
    {
        $y8 = \Drupal::config("\x6d\x69\x6e\x69\157\x72\x61\x6e\147\x65\x5f\163\x61\x6d\154\x2e\x73\x65\164\164\x69\156\x67\163");
        $Xm = Utilities::getBaseUrl();
        $UN = Utilities::getIssuer();
        $zG = Utilities::getAcsUrl();
        $aS = Utilities::getPublicCertificate();
        $MZ = preg_replace("\x2f\133\15\xa\135\x2b\x2f", '', $aS);
        $MZ = str_replace("\55\55\x2d\55\55\x42\105\107\111\x4e\x20\103\105\x52\124\111\106\x49\x43\101\124\x45\x2d\x2d\55\x2d\x2d", '', $MZ);
        $MZ = str_replace("\55\x2d\x2d\55\x2d\105\x4e\x44\x20\103\105\x52\x54\111\x46\111\103\101\x54\x45\x2d\55\55\55\55", '', $MZ);
        $MZ = str_replace("\x2d\x2d\55\x2d\55\x42\x45\107\x49\x4e\40\120\x55\x42\114\111\103\x20\113\x45\x59\55\55\55\x2d\55", '', $MZ);
        $MZ = str_replace("\x2d\55\x2d\x2d\x2d\x45\116\x44\x20\x50\125\102\114\111\103\x20\x4b\105\x59\x2d\x2d\x2d\x2d\55", '', $MZ);
        $MZ = str_replace("\x20", '', $MZ);
        if (isset($_REQUEST["\x64\x6f\167\x6e\154\x6f\x61\144\103\145\162\x74\151\146\151\x63\x61\x74\x65"]) && $_REQUEST["\144\x6f\x77\156\154\x6f\141\144\x43\145\x72\164\x69\x66\151\x63\141\164\145"] && boolval($_REQUEST["\144\x6f\167\156\154\157\x61\144\x43\x65\162\164\x69\x66\151\x63\141\164\x65"])) {
            goto PZ;
        }
        if (isset($_REQUEST["\x64\157\x77\156\x6c\x6f\141\x64"]) && $_REQUEST["\x64\x6f\x77\x6e\x6c\x6f\x61\144"] && boolval($_REQUEST["\x64\x6f\x77\x6e\154\157\141\x64"])) {
            goto dq;
        }
        $Nf = "\103\x6f\156\x74\x65\x6e\164\x2d\x54\x79\160\x65\x3a\x20\x74\x65\170\164\57\x78\x6d\x6c";
        goto hh;
        PZ:
        $Nf = "\x43\157\156\164\x65\156\164\x2d\104\151\x73\x70\157\163\151\x74\151\x6f\x6e\x3a\x20\141\164\164\141\143\150\155\x65\156\164\73\x20\146\x69\154\145\x6e\x61\x6d\145\x3d\x22\163\160\x2d\x63\145\162\x74\151\x66\151\143\141\164\145\56\143\x72\164\x22";
        header($Nf);
        echo xss::filter($aS);
        exit;
        goto hh;
        dq:
        $Nf = "\103\x6f\x6e\x74\x65\156\x74\55\104\151\x73\x70\157\163\x69\164\x69\x6f\156\x3a\40\x61\x74\164\x61\143\x68\155\x65\x6e\164\73\40\x66\x69\x6c\x65\x6e\x61\x6d\145\75\x22\x4d\x65\164\141\144\x61\x74\141\x2e\170\155\x6c\x22";
        hh:
        header($Nf);
        echo "\74\77\x78\155\154\x20\x76\x65\x72\163\x69\x6f\x6e\x3d\42\61\x2e\x30\42\77\76\xd\12\x20\x20\40\40\40\40\x20\x20\74\x6d\144\72\105\156\x74\x69\x74\x79\104\x65\163\143\x72\151\x70\x74\157\x72\40\x78\155\154\156\x73\x3a\x6d\144\x3d\42\x75\162\156\72\157\x61\x73\x69\x73\72\156\141\x6d\x65\x73\x3a\164\x63\72\123\x41\115\114\x3a\62\56\x30\72\155\x65\164\141\144\x61\164\x61\42\x20\166\x61\x6c\151\144\125\156\164\x69\154\x3d\42\x32\x30\62\64\x2d\x30\63\55\x32\x37\x54\x32\x33\x3a\65\71\72\65\x39\132\x22\40\x63\x61\143\x68\x65\104\165\162\141\164\151\x6f\x6e\x3d\x22\x50\124\61\x34\64\66\x38\x30\70\x37\x39\x32\x53\42\40\x65\x6e\164\x69\164\x79\x49\x44\75\x22" . $UN . "\42\76\15\12\x20\40\x20\x20\x20\40\40\x20\x20\x20\74\x6d\x64\x3a\123\120\123\123\x4f\104\145\163\143\162\x69\x70\164\x6f\162\40\101\x75\164\150\x6e\x52\x65\161\x75\x65\163\164\x73\123\151\147\156\145\x64\x3d\x22\x74\162\165\x65\42\40\127\x61\156\164\101\x73\163\x65\162\164\151\x6f\x6e\x73\123\x69\147\x6e\145\x64\x3d\42\164\162\165\x65\x22\x20\160\x72\x6f\x74\x6f\x63\157\154\123\x75\160\x70\x6f\162\x74\x45\x6e\x75\x6d\145\162\141\x74\151\x6f\156\75\x22\x75\162\156\x3a\157\x61\163\x69\x73\72\156\x61\155\145\163\x3a\x74\x63\x3a\123\101\x4d\114\x3a\62\x2e\60\x3a\160\x72\157\164\x6f\143\157\x6c\x22\x3e\15\12\x20\x20\x20\x20\40\x20\x20\40\x20\40\x20\x20\x3c\155\x64\72\113\145\171\x44\145\163\x63\x72\151\160\164\x6f\162\x20\x75\x73\x65\75\42\x73\x69\147\156\151\x6e\147\x22\76\xd\xa\x20\40\x20\40\40\40\x20\40\40\x20\x20\40\x20\x20\x3c\x64\163\72\x4b\x65\171\111\156\x66\157\x20\x78\x6d\x6c\156\163\72\x64\x73\x3d\42\150\164\x74\160\72\x2f\57\167\167\x77\56\x77\63\x2e\157\162\147\x2f\x32\x30\60\x30\x2f\60\71\x2f\170\x6d\154\x64\x73\151\147\x23\42\76\xd\xa\x20\40\x20\40\40\x20\x20\x20\x20\40\x20\x20\x20\x20\x20\x20\74\144\163\x3a\130\65\x30\71\x44\141\164\141\76\15\12\x20\x20\x20\40\x20\40\x20\x20\40\40\40\40\40\40\x20\40\x20\40\74\144\163\72\130\x35\60\x39\x43\x65\x72\164\x69\146\151\143\x61\164\x65\x3e" . $MZ . "\74\57\x64\163\x3a\130\x35\x30\x39\103\145\x72\x74\151\x66\151\x63\141\164\145\x3e\15\12\x20\40\40\x20\x20\x20\40\x20\40\40\x20\x20\x20\x20\40\40\74\x2f\x64\x73\72\x58\x35\60\71\x44\141\x74\141\76\15\12\40\40\40\x20\x20\x20\x20\x20\x20\40\x20\x20\x20\40\74\x2f\144\163\x3a\x4b\145\171\x49\156\146\x6f\76\xd\xa\40\x20\40\x20\40\40\40\x20\x20\x20\40\40\74\57\155\144\72\x4b\x65\171\x44\145\163\143\x72\151\160\x74\157\x72\76\15\12\x20\40\x20\40\40\40\40\40\x20\x20\40\40\74\x6d\144\x3a\113\x65\171\x44\145\163\x63\162\x69\x70\164\x6f\162\40\165\163\145\75\42\x65\x6e\x63\x72\171\x70\164\x69\157\156\x22\x3e\xd\12\x20\40\x20\x20\x20\40\x20\x20\x20\40\40\40\40\x20\74\144\x73\72\x4b\145\x79\x49\x6e\146\157\x20\x78\155\x6c\x6e\163\72\144\163\75\x22\150\x74\x74\x70\72\x2f\x2f\x77\x77\167\x2e\x77\x33\56\157\x72\147\x2f\62\60\x30\x30\57\60\x39\x2f\170\x6d\154\144\x73\151\x67\x23\x22\76\xd\xa\x20\40\x20\40\x20\40\40\x20\40\x20\x20\x20\x20\40\40\40\x3c\x64\163\72\x58\x35\60\x39\104\141\x74\x61\76\15\12\40\40\40\x20\x20\40\x20\40\x20\x20\40\40\40\x20\40\40\40\x20\x3c\x64\x73\x3a\x58\x35\60\71\x43\145\162\x74\x69\146\x69\x63\141\x74\145\76" . $MZ . "\74\57\x64\163\72\130\x35\x30\71\x43\145\162\x74\151\146\x69\x63\141\164\145\x3e\xd\xa\40\x20\40\x20\40\x20\x20\40\40\40\x20\x20\40\40\40\x20\x3c\x2f\x64\163\x3a\130\x35\60\71\x44\141\164\x61\x3e\xd\12\40\x20\x20\x20\x20\x20\x20\x20\x20\40\x20\x20\40\x20\74\57\x64\163\72\x4b\145\x79\111\156\146\157\76\15\12\40\x20\x20\40\40\40\40\x20\x20\40\x20\x20\74\57\x6d\x64\72\113\145\x79\104\x65\163\143\162\151\x70\164\157\x72\76\xd\xa\x20\40\40\40\x20\40\40\40\x20\40\x20\x20\74\x6d\x64\x3a\x53\x69\x6e\x67\154\145\114\157\147\x6f\165\164\123\145\162\x76\151\x63\x65\40\102\x69\x6e\x64\x69\156\x67\x3d\42\x75\162\156\x3a\x6f\141\x73\151\163\72\x6e\x61\155\145\163\72\164\x63\x3a\x53\x41\x4d\x4c\72\x32\56\x30\x3a\x62\x69\x6e\144\x69\x6e\147\x73\x3a\x48\x54\x54\120\55\120\117\123\x54\x22\x20\114\157\143\141\x74\151\x6f\x6e\x3d\x22" . $Xm . "\57\165\x73\x65\x72\x2f\154\x6f\x67\157\x75\x74\42\57\x3e\15\xa\40\40\40\40\40\40\x20\40\x20\x20\40\40\74\x6d\144\x3a\123\x69\x6e\147\x6c\x65\114\157\147\x6f\165\x74\x53\145\162\x76\x69\143\145\x20\102\x69\x6e\x64\151\156\147\75\x22\x75\x72\156\72\157\x61\x73\151\x73\72\x6e\141\x6d\x65\163\72\x74\143\72\123\101\115\114\72\x32\x2e\60\x3a\x62\x69\156\x64\x69\156\147\x73\x3a\x48\124\124\x50\55\x52\145\144\151\162\145\x63\x74\42\40\114\157\143\x61\x74\151\x6f\x6e\x3d\x22" . $Xm . "\x2f\165\x73\x65\x72\x2f\154\157\147\x6f\x75\164\x22\57\x3e\15\12\x20\40\40\x20\x20\x20\40\40\x20\x20\40\x20\x3c\x6d\144\x3a\116\141\x6d\145\111\x44\106\157\x72\x6d\141\164\76\165\x72\x6e\x3a\157\141\163\151\x73\72\156\x61\x6d\x65\x73\x3a\164\143\x3a\x53\101\x4d\x4c\x3a\x31\56\x31\72\x6e\141\x6d\x65\151\x64\x2d\146\157\162\x6d\x61\164\x3a\145\x6d\141\x69\x6c\x41\144\144\x72\145\163\163\x3c\57\x6d\144\x3a\x4e\141\x6d\x65\111\104\106\157\162\x6d\141\164\x3e\15\xa\40\40\x20\40\40\40\40\x20\40\40\40\x20\x3c\155\144\72\x4e\x61\155\x65\111\104\x46\157\x72\x6d\x61\164\76\165\162\156\72\157\x61\163\x69\163\72\156\141\x6d\x65\x73\x3a\x74\x63\72\123\101\x4d\x4c\72\x32\56\x30\x3a\156\141\155\145\151\144\55\146\x6f\x72\155\x61\x74\72\x75\x6e\163\160\145\143\151\146\151\x65\144\74\57\x6d\x64\72\116\x61\x6d\x65\111\104\106\x6f\x72\x6d\x61\x74\76\15\xa\40\x20\x20\40\40\x20\40\x20\40\40\40\x20\x3c\x6d\x64\72\x4e\141\x6d\145\x49\104\106\157\162\155\141\x74\76\x75\x72\x6e\x3a\x6f\x61\163\151\163\72\156\141\x6d\x65\x73\x3a\x74\x63\72\x53\101\115\x4c\x3a\62\x2e\60\x3a\x6e\x61\x6d\145\151\x64\x2d\x66\157\x72\x6d\141\164\72\164\x72\x61\156\163\x69\145\156\x74\x3c\x2f\155\144\72\x4e\141\x6d\x65\111\x44\106\x6f\162\155\141\x74\x3e\xd\12\40\x20\40\x20\x20\40\40\40\40\x20\40\x20\x3c\155\x64\72\101\163\x73\145\x72\164\151\157\156\x43\157\156\x73\x75\x6d\x65\x72\x53\x65\162\166\151\143\x65\x20\102\151\x6e\x64\151\156\x67\x3d\x22\165\x72\156\x3a\x6f\x61\x73\151\x73\x3a\x6e\141\155\145\163\x3a\x74\143\72\x53\101\115\x4c\x3a\62\56\60\72\x62\x69\156\x64\151\x6e\x67\163\x3a\110\124\x54\120\x2d\x50\117\123\x54\x22\40\114\x6f\x63\141\164\151\x6f\x6e\x3d\x22" . $zG . "\x22\x20\x69\156\x64\x65\170\x3d\42\x31\42\x2f\x3e\15\12\x20\x20\x20\40\x20\40\40\40\40\40\74\x2f\155\x64\x3a\123\x50\x53\x53\117\104\145\x73\143\162\x69\x70\164\x6f\162\x3e\xd\12\40\x20\40\40\x20\40\40\x20\x20\x20\x3c\x6d\144\x3a\117\x72\147\141\156\x69\172\141\x74\x69\x6f\x6e\76\xd\xa\x20\x20\40\x20\40\40\40\x20\x20\40\40\40\74\155\144\x3a\117\162\x67\141\x6e\151\x7a\x61\164\151\x6f\x6e\116\x61\155\x65\x20\170\x6d\x6c\x3a\154\141\156\x67\75\x22\145\x6e\55\x55\123\42\76" . $y8->get("\x6d\157\x5f\x73\141\x6d\154\x5f\155\145\164\x61\144\141\164\141\x5f\x4f\x72\x67\141\156\x69\x7a\141\164\151\157\x6e\x4e\x61\155\x65") . "\74\x2f\x6d\x64\72\x4f\162\x67\x61\156\151\172\141\x74\151\157\156\x4e\x61\155\145\x3e\15\xa\x20\x20\x20\40\x20\40\x20\40\x20\40\40\x20\x3c\155\144\72\117\x72\147\x61\x6e\151\172\141\164\151\157\156\x44\151\163\x70\x6c\141\171\116\141\x6d\145\x20\170\155\x6c\72\154\141\156\x67\x3d\x22\x65\156\x2d\125\x53\x22\76" . $y8->get("\x6d\x6f\137\163\141\155\154\x5f\x4f\x72\147\141\156\x69\172\141\164\x69\x6f\x6e\x44\x69\163\160\x6c\141\171\x4e\141\155\x65") . "\74\57\155\x64\x3a\117\x72\x67\x61\156\x69\172\x61\164\151\x6f\x6e\x44\x69\163\x70\x6c\141\x79\116\x61\x6d\x65\76\xd\xa\40\40\40\40\x20\x20\x20\x20\40\40\x20\40\x3c\x6d\144\x3a\117\162\x67\x61\156\x69\x7a\x61\x74\x69\x6f\x6e\125\x52\x4c\x20\x78\155\x6c\x3a\x6c\141\x6e\147\75\x22\x65\x6e\x2d\125\123\42\76" . $y8->get("\155\157\x5f\x73\x61\x6d\154\x5f\x4f\x72\147\x61\156\x69\x7a\141\x74\x69\x6f\156\x55\x52\114") . "\74\57\155\144\x3a\x4f\162\x67\x61\x6e\x69\172\141\164\151\x6f\156\125\122\x4c\76\15\12\x20\40\40\40\40\x20\40\40\40\x20\x3c\57\155\x64\72\117\x72\147\x61\x6e\151\x7a\141\x74\151\x6f\156\76\xd\xa\x20\x20\x20\x20\x20\40\40\40\x20\x20\x3c\x6d\144\x3a\x43\x6f\156\x74\x61\143\x74\120\145\162\x73\157\156\x20\x63\x6f\156\164\x61\x63\x74\124\x79\x70\x65\75\x22\164\145\x63\150\156\151\143\x61\x6c\x22\x3e\15\12\x20\40\x20\40\40\40\40\x20\40\40\40\40\74\x6d\x64\x3a\107\x69\x76\x65\156\116\x61\x6d\145\x3e" . $y8->get("\x6d\x6f\x5f\163\141\155\154\137\103\x6f\x6e\x74\x61\143\x74\120\x65\162\163\157\156\x54\145\143\150\156\x69\143\x61\154\x4e\x61\x6d\x65") . "\x3c\x2f\155\x64\x3a\x47\151\166\x65\x6e\x4e\x61\155\145\x3e\15\xa\x20\40\x20\40\40\x20\40\x20\40\40\x20\40\74\x6d\144\72\x45\155\x61\x69\x6c\x41\144\144\x72\x65\x73\163\x3e" . $y8->get("\155\x6f\137\x73\141\155\x6c\137\x43\157\x6e\x74\141\143\164\x50\x65\162\x73\157\156\124\145\x63\x68\156\151\x63\x61\154\105\x6d\141\x69\x6c") . "\74\57\155\x64\72\105\x6d\141\151\x6c\101\x64\x64\162\145\163\x73\x3e\15\12\x20\40\x20\40\40\40\x20\40\40\40\x3c\x2f\155\x64\72\x43\x6f\x6e\164\141\x63\x74\x50\x65\162\163\x6f\156\x3e\xd\xa\x20\x20\x20\40\40\x20\40\40\x20\40\x3c\155\144\72\103\x6f\x6e\164\141\143\x74\x50\145\162\163\157\x6e\40\143\x6f\x6e\x74\x61\143\x74\x54\171\160\145\75\x22\x73\x75\x70\160\157\162\164\x22\x3e\xd\xa\40\x20\40\40\x20\x20\40\40\x20\40\x20\x20\x3c\x6d\x64\72\x47\151\166\x65\x6e\116\141\155\x65\76" . $y8->get("\x6d\157\137\x73\x61\x6d\154\x5f\x43\x6f\156\x74\141\143\x74\120\x65\x72\163\157\156\123\165\160\160\157\x72\164\x4e\x61\155\145") . "\x3c\57\155\x64\x3a\107\x69\166\x65\x6e\x4e\x61\x6d\145\76\xd\12\40\40\40\x20\x20\40\x20\40\40\40\x20\x20\74\x6d\x64\72\105\x6d\141\x69\154\x41\x64\144\x72\x65\x73\x73\x3e" . $y8->get("\x6d\157\137\163\x61\x6d\x6c\137\103\x6f\x6e\x74\141\143\164\x50\145\x72\x73\157\x6e\x53\x75\x70\x70\157\x72\164\105\x6d\141\151\154") . "\74\57\155\x64\72\105\x6d\141\151\x6c\x41\144\144\162\145\x73\x73\x3e\xd\xa\x20\40\x20\40\x20\x20\x20\40\x20\x20\74\57\155\x64\x3a\103\x6f\156\164\141\x63\x74\120\x65\162\x73\157\x6e\x3e\xd\xa\40\x20\x20\x20\40\x20\x20\x20\x3c\57\155\x64\72\105\x6e\164\151\164\x79\x44\145\x73\143\162\151\160\x74\x6f\162\76";
        exit;
    }
}
