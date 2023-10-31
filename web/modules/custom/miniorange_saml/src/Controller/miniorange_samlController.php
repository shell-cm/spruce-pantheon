<?php


namespace Drupal\miniorange_saml\Controller;

use Drupal\Core\Field\EntityReferenceFieldItemList;
use Drupal\field\Entity\FieldStorageConfig;
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
    public function __construct(FormBuilder $is)
    {
        $this->formBuilder = $is;
    }
    public static function saml_login($Qd = '', $ou = '')
    {
        $f5 = \Drupal::config("\x6d\151\x6e\x69\157\162\x61\x6e\147\x65\x5f\x73\141\155\154\x2e\163\x65\164\x74\x69\x6e\x67\x73");
        if (!(!$f5->get("\155\x69\x6e\151\x6f\162\x61\156\x67\x65\x5f\x73\141\x6d\154\137\145\156\x61\142\154\145\137\154\x6f\x67\x69\x6e") && strcasecmp($ou, "\x74\x65\163\x74\x56\141\x6c\151\x64\x61\164\x65") != 0)) {
            goto OX;
        }
        $AM = "\x43\141\156\40\156\x6f\164\x20\151\156\x69\164\x69\141\164\145\x20\x53\x53\117\x2e";
        $nl = '';
        $YK = "\123\123\117\x20\x69\x73\x20\156\x6f\x74\40\145\x6e\141\x62\x6c\x65\x64\56";
        Utilities::showErrorMessage($AM, $nl, $YK, TRUE);
        return new Response();
        OX:
        \Drupal::service("\x70\x61\147\x65\137\x63\141\143\150\145\137\153\151\154\154\x5f\x73\x77\x69\164\x63\x68")->trigger();
        $Tf = $f5->get("\155\151\156\x69\x6f\162\141\x6e\x67\x65\137\x73\x61\x6d\154\137\144\x65\x66\141\x75\x6c\164\137\x72\145\x6c\x61\171\163\x74\x61\164\x65");
        $BI = $f5->get("\x6d\x69\x6e\x69\157\x72\141\156\x67\x65\137\163\x61\155\154\x5f\162\x65\161\x75\145\x73\x74\137\x73\x69\147\156\145\x64");
        $dQ = $f5->get("\x73\145\x63\x75\x72\151\x74\x79\137\163\x69\147\x6e\x61\164\165\x72\145\x5f\x61\154\x67\x6f\x72\151\164\150\155");
        $DZ = $f5->get("\x6d\151\156\x69\157\162\x61\156\x67\x65\137\x73\x61\x6d\154\137\150\x74\x74\160\x5f\x62\151\x6e\144\x69\156\147");
        $Wn = isset($_REQUEST["\x64\145\163\x74\151\156\141\x74\151\x6f\x6e"]) ? trim($_REQUEST["\x64\x65\163\164\x69\x6e\141\x74\151\x6f\x6e"], "\47") : '';
        if (empty($ou)) {
            goto wx;
        }
        $Wn = $ou;
        wx:
        if (!empty($Wn)) {
            goto bV;
        }
        $Wn = $Tf;
        bV:
        if (!empty($Wn)) {
            goto Ic;
        }
        $Wn = $Qd;
        Ic:
        if (!(empty($Wn) && isset($_SERVER["\x48\x54\124\120\x5f\122\105\x46\x45\x52\x45\122"]))) {
            goto V0;
        }
        $Wn = $_SERVER["\x48\124\x54\x50\137\x52\x45\x46\105\x52\105\122"];
        V0:
        if (!empty($Wn)) {
            goto L_;
        }
        $Wn = Utilities::getBaseUrl();
        L_:
        $se = Utilities::getAcsUrl();
        $WI = $f5->get("\x6d\151\156\151\x6f\162\x61\156\x67\x65\x5f\x73\x61\155\x6c\137\x69\144\x70\x5f\x6c\157\147\151\x6e\137\x75\x72\x6c");
        $wi = $f5->get("\155\151\156\x69\157\162\141\156\147\x65\137\x73\x61\155\x6c\x5f\x6e\x61\155\145\x69\x64\137\146\x6f\162\155\x61\x74");
        $J4 = new MiniOrangeAuthnRequest();
        $J4->initiateLogin($se, $WI, Utilities::getIssuer(), $Wn, $wi, $DZ, $BI, $dQ);
        return new Response();
    }
    public static function create(ContainerInterface $fa)
    {
        return new static($fa->get("\146\x6f\162\x6d\x5f\142\165\x69\154\144\145\162"));
    }
    public function saml_response()
    {
        global $base_url;
        global $gW;
        if (isset($_GET["\123\x41\115\x4c\x52\x65\x73\x70\x6f\156\163\x65"])) {
            goto xK;
        }
        $f5 = \Drupal::config("\x6d\151\x6e\x69\x6f\162\x61\x6e\x67\145\x5f\x73\141\155\154\56\x73\145\x74\164\151\x6e\147\163");
        $ik = $f5->get("\155\151\156\x69\157\x72\x61\x6e\147\145\137\x73\x61\x6d\x6c\x5f\143\x75\x73\x74\x6f\155\137\x61\164\x74\x72\163\x5f\x6d\141\160\x5f\x61\162\162") !== NULL ? json_decode($f5->get("\155\x69\156\151\x6f\162\141\156\147\145\x5f\x73\141\x6d\x6c\137\143\165\x73\164\157\x6d\x5f\141\164\x74\x72\x73\137\155\x61\160\137\141\162\x72"), true) : [];
        $WJ = new MiniOrangeAcs();
        $DH = $f5->get("\155\x69\x6e\157\x72\141\156\147\x65\137\x73\141\x6d\154\x5f\x63\x75\x73\164\157\155\145\x72\137\x61\144\x6d\151\x6e\137\x66\162\x61\165\144\x5f\x63\150\145\143\153");
        $cZ = $f5->get("\x6d\x69\156\151\157\x72\x61\156\x67\x65\x5f\163\141\x6d\154\x5f\143\165\163\164\x6f\155\x65\162\x5f\x61\x64\155\151\x6e\x5f\x74\x6f\x6b\145\x6e");
        $QB = $f5->get("\155\x69\x6e\x69\x6f\x72\141\156\x67\x65\137\x73\x61\x6d\154\137\x63\165\163\x74\157\155\x65\162\x5f\141\144\x6d\x69\156\137\x65\155\x61\151\x6c");
        $pN = \Drupal::request()->server->get("\104\x4f\x43\125\x4d\x45\116\124\137\x52\x4f\117\124") . $gW;
        $XE = trim($base_url, "\x2f");
        if (preg_match("\43\x5e\150\164\x74\160\50\x73\51\x3f\72\57\x2f\43", $XE)) {
            goto se;
        }
        $XE = "\x68\164\x74\x70\72\57\x2f" . $XE;
        se:
        $JY = parse_url($XE);
        $Qi = isset($JY["\160\141\x74\150"]) ? $JY["\160\141\x74\x68"] : '';
        $y6 = preg_replace("\57\136\167\167\x77\x5c\x2e\57", '', $JY["\x68\x6f\x73\x74"] . $Qi);
        $u2 = $pN . $y6;
        $Bb = $f5->get("\155\151\x6e\151\157\162\141\156\147\x65\x5f\163\x61\155\154\x5f\x69\x73\x4d\x75\154\164\151\123\x69\x74\x65\x50\x6c\x75\147\151\156\122\x65\161\x75\x65\x73\x74\x65\x64") == true;
        if (($Bb || $u2 == AESEncryption::decrypt_data($DH, $cZ) || $u2 == AESEncryption::decrypt_data($DH, $cZ, "\101\x45\123\x2d\61\62\x38\55\x45\x43\x42")) && $QB != null && $QB != '') {
            goto i6;
        }
        if ($QB != null && $QB != '') {
            goto Lh;
        }
        if (!($QB == null || $QB == '')) {
            goto Ek;
        }
        $AM = "\x59\157\165\40\x61\x72\x65\x20\156\x6f\164\40\154\x6f\x67\x67\145\144\40\x69\156\x2e";
        $nl = "\x50\x6c\x65\141\x73\x65\40\154\x6f\x67\151\x6e\40\146\151\x72\x73\x74\40\164\157\40\141\143\x74\151\166\x61\x74\x65\40\x73\151\156\x67\x6c\145\x20\163\x69\x67\x6e\40\157\156\x2e";
        $YK = "\x4d\141\153\x65\40\x73\165\x72\x65\40\171\157\x75\40\x68\x61\166\x65\x20\154\x6f\x67\147\145\x64\x20\x69\x6e\57\x20\122\145\147\151\163\164\x65\x72\x20\151\156\40\x74\x6f\40\x6d\x6f\144\x75\154\145\56";
        Utilities::showErrorMessage($AM, $nl, $YK);
        Ek:
        goto fQ;
        Lh:
        if (isset($_POST["\122\x65\154\x61\171\x53\x74\x61\164\145"]) && $_POST["\x52\145\154\x61\x79\x53\x74\x61\x74\145"] == "\164\x65\x73\x74\x56\141\x6c\x69\144\x61\164\145") {
            goto jj;
        }
        $AM = "\x57\145\40\143\x6f\165\154\x64\40\156\157\164\x20\163\151\x67\x6e\40\171\157\x75\40\151\x6e\x2e";
        $nl = "\120\154\x65\141\x73\145\40\103\157\156\x74\141\x63\164\40\x79\157\165\162\x20\x61\144\x6d\151\156\151\163\x74\x72\141\164\x6f\x72\x2e";
        Utilities::showErrorMessage($AM, $nl, "\x2d");
        goto fe;
        jj:
        $AM = "\x4c\151\143\x65\156\x73\145\x20\x6b\x65\171\40\171\x6f\x75\x20\x68\141\166\x65\40\x65\x6e\164\x65\x72\x65\x64\x20\x68\141\x73\x20\141\154\162\145\141\144\x79\x20\142\145\145\x6e\40\165\x73\145\144\x2e";
        $nl = "\120\154\x65\141\163\x65\40\x65\156\164\x65\162\x20\141\40\x6b\x65\171\x20\x77\x68\x69\x63\x68\40\150\x61\163\x20\156\157\164\x20\142\x65\145\156\40\x75\x73\145\144\40\x62\145\146\x6f\162\x65\40\x6f\156\x20\141\x6e\171\40\x6f\164\150\145\162\x20\x69\x6e\x73\x74\141\x6e\x63\x65\40\x6f\162\x20\151\x66\40\171\x6f\x75\x20\150\141\166\145\40\x65\170\141\165\x73\x74\x65\x64\x20\x61\154\154\x20\171\x6f\165\x72\40\153\145\171\163\x20\164\x68\x65\x6e\x20\142\x75\x79\x20\155\x6f\x72\145\x20\154\151\x63\x65\156\x73\x65\x20\146\162\x6f\x6d\40\x4c\151\143\145\156\163\x69\156\147\56";
        Utilities::showErrorMessage($AM, $nl, "\55");
        fe:
        fQ:
        goto Y3;
        i6:
        \Drupal::moduleHandler()->invokeAll("\146\x6f\x72\x77\x61\x72\144\137\x72\145\x73\x70\x6f\x6e\163\x65", [$_POST]);
        $Bj = $WJ->processSamlResponse($_POST, $ik);
        $Yq = $Bj["\162\145\163\160\x6f\156\163\145"];
        $Wm = $Bj["\162\145\163\157\165\x72\143\145\163"];
        Y3:
        if (!(MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION && \Drupal\miniorange_saml\HigherUtilities::Is_Restricted_Domain($Yq["\145\155\141\x69\154"]) === TRUE)) {
            goto Sg;
        }
        $AM = "\131\x6f\x75\40\141\162\x65\40\156\157\x74\x20\x61\x6c\154\x6f\167\145\144\x20\164\x6f\x20\154\157\x67\151\156\x20";
        $nl = "\x50\154\x65\141\163\x65\40\103\157\x6e\164\x61\x63\x74\x20\x79\157\165\x72\40\141\144\155\x69\156\151\x73\164\x72\141\164\x6f\x72\x2e";
        $YK = "\x59\157\165\162\40\x64\x6f\155\x61\x69\x6e\x20\x6d\141\x79\40\x62\x65\40\x62\154\157\143\x6b\x65\x64\40\x62\171\x20\x61\x64\x6d\x69\x6e";
        Utilities::showErrorMessage($AM, $nl, $YK);
        Sg:
        if ($f5->get("\x6d\151\156\x69\x6f\162\x61\x6e\x67\x65\x5f\x73\x61\x6d\x6c\x5f\x6c\x6f\x61\144\x5f\x75\163\x65\162") == 1) {
            goto H_;
        }
        $e5 = user_load_by_name($Yq["\165\163\x65\162\156\141\x6d\145"]);
        goto wd;
        H_:
        $e5 = user_load_by_mail($Yq["\145\x6d\x61\151\154"]);
        wd:
        $mB = 0;
        if (!($e5 == NULL)) {
            goto Dp;
        }
        $FQ = $f5->get("\155\x69\156\151\x6f\162\x61\156\x67\x65\137\163\141\155\154\137\x64\x69\x73\x61\142\x6c\x65\137\141\165\x74\157\143\x72\x65\141\x74\145\137\x75\163\145\162\163");
        if ($FQ) {
            goto hE;
        }
        $T3 = \Drupal::service("\x70\141\163\x73\x77\x6f\x72\x64\137\147\145\156\x65\162\141\164\x6f\162")->generate(8);
        $Md = $f5->get("\x6d\151\x6e\151\157\x72\x61\x6e\x67\x65\137\163\141\155\154\x5f\144\145\146\x61\165\x6c\164\137\x72\x6f\x6c\x65");
        $Gn = ["\156\x61\155\145" => $Yq["\x75\163\145\162\x6e\x61\155\145"], "\x6d\141\x69\x6c" => $Yq["\145\155\x61\151\154"], "\160\141\x73\x73" => $T3, "\163\x74\x61\x74\x75\x73" => 1];
        $e5 = User::create($Gn);
        $e5->save();
        if (!($Md != "\x61\x75\x74\x68\x65\x6e\164\x69\x63\x61\164\x65\144" && $f5->get("\155\151\156\151\x6f\x72\141\156\147\145\137\163\x61\155\x6c\x5f\145\156\141\142\x6c\x65\137\162\157\x6c\145\155\x61\x70\160\151\156\x67"))) {
            goto hr;
        }
        $e5->addRole($Md);
        $e5->save();
        hr:
        goto s8;
        hE:
        $AM = "\x41\143\143\x6f\x75\x6e\x74\40\x64\157\x65\x73\x20\156\157\x74\40\145\170\x69\163\x74\x20\x77\151\164\x68\x20\x79\157\x75\x72\x20\x75\163\x65\x72\x6e\x61\x6d\x65\56";
        $nl = "\120\x6c\145\x61\163\145\x20\103\x6f\156\164\x61\x63\164\40\171\x6f\x75\x72\x20\141\144\155\151\156\x69\163\x74\162\x61\x74\157\162\56";
        $YK = "\101\165\164\x6f\x20\x63\x72\x65\x61\164\x69\157\x6e\40\157\146\40\x75\x73\x65\162\x20\x69\x73\40\156\157\164\x20\141\154\154\157\x77\145\144\x20\x69\146\x20\x75\163\x65\162\40\144\157\145\x73\x20\x6e\x6f\x74\40\145\x78\x69\163\x74\x2e";
        Utilities::showErrorMessage($AM, $nl, $YK);
        s8:
        Dp:
        $t7 = array();
        $t7 = $Yq["\143\165\x73\164\157\155\x46\x69\x65\x6c\x64\x41\164\x74\162\x69\x62\x75\x74\x65\163"];
        $e5 = User::load($e5->id());
        $kq = $f5->get("\x6d\151\x6e\x69\x6f\162\141\156\147\x65\137\163\x61\x6d\154\137\x63\x75\163\164\157\155\x5f\141\164\x74\x72\x73\x5f\155\141\x70\137\x73\x65\160") !== NULL ? json_decode($f5->get("\155\151\156\151\157\x72\x61\x6e\147\145\x5f\163\141\x6d\154\x5f\143\x75\163\x74\x6f\x6d\137\141\164\x74\162\163\137\x6d\x61\160\137\x73\x65\160")) : '';
        foreach ($t7 as $yQ => $Ox) {
            $Id = $e5->get($yQ);
            $X0 = $Id->getFieldDefinition();
            $cB = $X0->getFieldStorageDefinition();
            if ($cB->getType() === "\145\156\164\x69\x74\171\x5f\x72\x65\146\145\162\145\156\x63\145") {
                goto Rz;
            }
            if (Utilities::isMultiple($yQ) && !is_null($kq->{$yQ})) {
                goto Nj;
            }
            if (!self::isBooleanField($yQ)) {
                goto DY;
            }
            $Ox = filter_var($Ox, FILTER_VALIDATE_BOOLEAN);
            DY:
            $hG = array($Ox);
            goto XQ;
            Nj:
            $hG = explode($kq->{$yQ}, $Ox);
            XQ:
            $e5->get($yQ)->setValue($hG);
            $e5->save();
            goto CS;
            Rz:
            $aM = $cB->getSetting("\164\141\162\x67\x65\x74\x5f\x74\x79\160\145");
            $no = $X0->getSetting("\150\x61\x6e\144\154\x65\x72\x5f\163\145\x74\x74\151\x6e\147\163");
            $rJ = \Drupal::entityTypeManager()->getStorage($aM)->loadMultiple(NULL);
            if (!isset($no["\164\141\x72\x67\x65\164\137\142\165\156\144\x6c\x65\x73"])) {
                goto VV;
            }
            if (Utilities::isMultiple($yQ) && !is_null($kq->{$yQ})) {
                goto CM;
            }
            $hG = array($Ox);
            goto aZ;
            CM:
            $hG = explode($kq->{$yQ}, $Ox);
            aZ:
            $E1 = [];
            $sY = [];
            foreach ($hG as $Ox) {
                $rJ = \Drupal::entityTypeManager()->getStorage($aM)->loadByProperties(["\x6e\141\155\145" => $Ox]);
                $HH = false;
                foreach ($rJ as $uz) {
                    if (!in_array($uz->bundle(), $no["\164\141\x72\147\145\x74\x5f\x62\x75\x6e\144\x6c\145\x73"])) {
                        goto z1;
                    }
                    $E1[] = $uz->id();
                    $HH = true;
                    z1:
                    Io:
                }
                jo:
                if ($HH) {
                    goto KV;
                }
                $sY[] = $Ox;
                KV:
                lx:
            }
            mR:
            $FX = isset($no["\x61\165\164\x6f\x5f\x63\x72\145\x61\164\145"]) ? $no["\x61\x75\164\x6f\137\x63\x72\145\x61\164\x65"] : false;
            $XT = isset($no["\141\x75\164\x6f\137\143\x72\145\x61\x74\x65\137\142\x75\x6e\x64\x6c\x65"]) ? $no["\x61\x75\x74\x6f\x5f\x63\162\x65\141\164\x65\137\142\165\156\x64\154\x65"] : '';
            if (!($FX && $aM == "\164\141\170\x6f\156\x6f\x6d\171\x5f\164\x65\x72\x6d")) {
                goto kh;
            }
            foreach ($sY as $bh) {
                $LH = Term::create(["\x6e\x61\x6d\x65" => $bh, "\x76\x69\144" => $XT]);
                $LH->save();
                $E1[] = $LH->id();
                Ny:
            }
            pf:
            kh:
            $Id->setValue($E1);
            $e5->save();
            VV:
            CS:
            UX:
        }
        Mp:
        if (!(!is_null($e5) && $f5->get("\155\151\156\x69\x6f\162\141\156\147\x65\137\163\x61\155\154\137\x65\156\x61\142\x6c\145\137\162\x6f\x6c\x65\155\141\160\160\151\x6e\147"))) {
            goto dw;
        }
        $zE = $f5->get("\x6d\x69\156\x69\157\162\141\156\x67\x65\137\163\141\155\154\x5f\x72\x6f\x6c\x65\137\155\x61\160\x70\151\156\147\x5f\x61\162\162") != null ? (array) json_decode($f5->get("\155\x69\156\151\x6f\162\x61\x6e\147\145\137\163\x61\155\x6c\137\x72\x6f\154\145\x5f\x6d\x61\160\x70\x69\x6e\x67\x5f\x61\x72\x72")) : [];
        $PH = array();
        $PH = $Yq["\x63\165\163\x74\x6f\155\106\151\145\x6c\144\122\157\x6c\145\x73"];
        $AL = \Drupal::configFactory()->getEditable("\x6d\x69\156\x69\x6f\162\x61\156\x67\145\137\163\x61\x6d\154\x2e\x73\x65\x74\164\151\x6e\147\163")->get("\155\151\x6e\151\157\162\141\x6e\147\x65\x5f\163\141\155\x6c\x5f\x64\151\x73\x61\x62\154\x65\x5f\162\157\154\x65\x5f\x75\160\x64\x61\x74\145");
        $g5 = $e5->getRoles();
        if ($AL) {
            goto Mg;
        }
        foreach ($g5 as $yQ => $Ox) {
            if (in_array($Ox, array_keys($zE))) {
                goto re;
            }
            if (!($Ox != $f5->get("\155\151\156\151\157\162\141\x6e\x67\145\x5f\x73\141\x6d\x6c\x5f\144\x65\146\x61\x75\154\x74\137\162\x6f\154\145"))) {
                goto X1;
            }
            $e5->removeRole($Ox);
            $e5->save();
            X1:
            re:
            ZV:
        }
        c8:
        Mg:
        foreach ($zE as $yQ => $Ox) {
            $cn = FALSE;
            $Rf = array();
            $tw = explode("\x3b", $Ox);
            foreach ($tw as $pC => $XG) {
                set_error_handler(function ($hZ, $f4, $fj, $Kj) {
                });
                $lQ = preg_match($XG, '');
                restore_error_handler();
                $Ss = !is_bool($lQ);
                if (!is_array($PH)) {
                    goto hX;
                }
                if ($Ss) {
                    goto QB;
                }
                if (in_array($XG, $PH)) {
                    goto v6;
                }
                goto Lm;
                QB:
                $Rf = preg_grep($XG, $PH);
                if (empty($Rf)) {
                    goto O7;
                }
                $cn = TRUE;
                O7:
                goto Lm;
                v6:
                $cn = TRUE;
                Lm:
                hX:
                hV:
            }
            W8:
            if ($cn && $yQ != "\x61\x75\164\x68\145\x6e\x74\x69\143\141\x74\145\x64") {
                goto yp;
            }
            $e5->removeRole($yQ);
            $e5->save();
            goto R5;
            yp:
            $e5->addRole($yQ);
            $e5->save();
            R5:
            ql:
        }
        ty:
        dw:
        $gu = $f5->get("\155\151\156\x69\157\162\x61\x6e\x67\145\137\163\x61\x6d\x6c\137\145\156\141\142\x6c\x65\x5f\x70\162\x6f\x66\x69\x6c\x65\x5f\x6d\141\160\160\x69\156\x67");
        if (!(MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION && $gu)) {
            goto Cl;
        }
        HigherUtilities::profileFieldMapping($e5, $Wm);
        Cl:
        if (user_is_blocked($Yq["\x75\x73\x65\x72\156\141\x6d\145"]) == FALSE) {
            goto gl;
        }
        $AM = "\x55\x73\145\162\40\102\154\x6f\x63\153\145\144\40\102\x79\40\x41\x64\155\x69\x6e\151\163\164\x72\141\164\x6f\x72\x2e";
        $nl = "\120\154\145\x61\163\x65\40\x43\157\x6e\x74\x61\x63\164\x20\171\x6f\x75\x72\x20\141\144\x6d\151\x6e\151\x73\164\162\141\x74\x6f\162\56";
        $YK = "\x54\x68\151\163\40\165\x73\145\x72\40\141\143\143\157\165\x6e\x74\40\x69\x73\x20\x6e\x6f\164\x20\x61\154\x6c\x6f\x77\x65\x64\40\164\157\40\154\157\x67\151\156\x2e";
        Utilities::showErrorMessage($AM, $nl, $YK);
        return new Response();
        goto mb;
        gl:
        if (!(array_key_exists("\162\145\x6c\141\x79\137\x73\164\x61\164\145", $Yq) && !empty($Yq["\162\x65\154\141\x79\137\x73\x74\141\164\x65"]))) {
            goto o1;
        }
        $s9 = $Yq["\x72\145\x6c\141\171\137\163\x74\x61\164\x65"];
        o1:
        $uB = Utilities::getBaseUrl();
        if (!(empty($s9) || $s9 == "\x2f")) {
            goto yP;
        }
        $s9 = $uB;
        yP:
        \Drupal::moduleHandler()->invokeAll("\151\x6e\x76\157\x6b\x65\137\155\x69\156\x69\x6f\162\x61\156\x67\x65\x5f\x32\146\x61\137\x62\145\x66\x6f\x72\145\x5f\154\157\x67\x69\156", [$e5]);
        \Drupal::moduleHandler()->invokeAll("\155\x69\x6e\151\157\162\x61\x6e\x67\x65\x5f\x73\x61\155\x6c\137\151\x64\160\x5f\x72\145\x73\x6f\x75\162\143\x65\163", [$e5, $Wm]);
        user_login_finalize($e5);
        $_SESSION["\x73\145\x73\x73\x69\x6f\156\x49\156\x64\x65\x78"] = $Yq["\163\145\163\x73\x69\157\x6e\111\156\x64\x65\x78"];
        $_SESSION["\x4e\x61\155\145\111\x44"] = $Yq["\116\141\155\x65\111\x44"];
        $_SESSION["\x6d\157\137\x73\x61\x6d\154"]["\x6c\157\147\147\145\144\x5f\x69\x6e\x5f\167\151\x74\x68\137\x69\144\x70"] = TRUE;
        if (!($f5->get("\x6d\151\156\x69\x6f\162\x61\x6e\147\145\137\163\141\155\x6c\x5f\x72\145\x73\164\162\151\x63\164\x5f\x72\145\144\151\162\x65\143\164\137\x6f\x75\x74\x73\151\144\145\x5f\144\157\x6d\141\151\x6e") == TRUE)) {
            goto s2;
        }
        $xp = parse_url($s9);
        $iN = parse_url($uB);
        $g8 = isset($iN["\150\157\163\x74"]) ? $iN["\150\157\x73\164"] : FALSE;
        $D7 = isset($xp["\x68\x6f\163\x74"]) ? $xp["\150\x6f\x73\164"] : FALSE;
        if (!($D7 !== FALSE && $g8 !== $D7)) {
            goto WM;
        }
        $Rp = $s9;
        $s9 = $uB;
        $Rb = $f5->get("\155\151\156\151\157\162\141\x6e\147\145\137\163\x61\x6d\x6c\x5f\x77\x68\151\x74\x65\154\151\x73\x74\137\x64\157\155\141\151\156\x73");
        $ps = explode("\x3b", $Rb);
        foreach ($ps as $Ej) {
            if (!($Ej == '' or $Ej == "\x2f")) {
                goto uA;
            }
            goto xY;
            uA:
            if (!(strpos($D7, trim($Ej)) !== false)) {
                goto Lc;
            }
            $s9 = $Rp;
            goto vS;
            Lc:
            xY:
        }
        vS:
        WM:
        s2:
        $Yq = new RedirectResponse($s9);
        $w7 = \Drupal::request();
        $w7->getSession()->save();
        $Yq->prepare($w7);
        \Drupal::service("\153\x65\162\156\x65\x6c")->terminate($w7, $Yq);
        $Yq->send();
        exit;
        return new Response();
        mb:
        goto Up;
        xK:
        $w7 = \Drupal::request();
        $w7->getSession()->clear();
        $Yq = new RedirectResponse(Utilities::getBaseUrl());
        $Yq->send();
        return new Response();
        Up:
        return new Response();
    }
    static function saml_logout()
    {
        $f5 = \Drupal::config("\155\x69\x6e\151\x6f\162\x61\156\147\145\x5f\163\141\x6d\x6c\56\x73\x65\x74\164\x69\x6e\x67\163");
        $dQ = $f5->get("\x73\x65\x63\x75\x72\x69\164\x79\x5f\163\151\147\x6e\141\x74\x75\x72\x65\x5f\x61\154\x67\157\x72\151\164\x68\x6d");
        $aa = Utilities::getBaseUrl();
        $pF = Utilities::getRedirectUrAfterLogout($aa);
        $rK = $f5->get("\155\151\x6e\x69\x6f\162\x61\156\x67\x65\x5f\163\x61\155\x6c\x5f\151\x64\x70\137\x6c\x6f\x67\x6f\165\164\137\165\162\x6c");
        $MB = $f5->get("\x6d\x69\156\151\157\162\141\156\147\x65\137\x73\x61\155\x6c\x5f\163\x6c\157\x5f\x68\x74\164\x70\137\142\x69\x6e\144\x69\x6e\x67");
        if (!empty($rK)) {
            goto M2;
        }
        $w7 = \Drupal::request();
        $w7->getSession()->clear();
        $Yq = new RedirectResponse($pF);
        $Yq->send();
        return new Response();
        goto CP;
        M2:
        if (!\Drupal::service("\x73\x65\x73\x73\x69\157\156")->getId() || \Drupal::service("\163\x65\163\x73\151\x6f\156")->getId() == '' || !isset($_SESSION)) {
            goto ZA;
        }
        if (!isset($_SESSION["\155\x6f\x5f\x73\x61\x6d\x6c"]["\x6c\x6f\147\x67\145\144\x5f\151\156\137\x77\x69\x74\150\137\x69\144\x70"])) {
            goto pE;
        }
        unset($_SESSION["\155\157\x5f\x73\141\155\x6c"]);
        $mT = $_SESSION["\x73\145\163\163\151\x6f\x6e\x49\156\x64\x65\170"];
        $Sj = $_SESSION["\116\x61\155\145\x49\x44"];
        Utilities::checkIfLogoutRequest($_REQUEST, $_GET);
        $WY = $aa;
        $Mm = Utilities::createLogoutRequest($Sj, Utilities::getIssuer(), $rK, $MB, $mT);
        $BI = $f5->get("\x6d\x69\x6e\x69\x6f\162\141\x6e\x67\x65\137\163\x61\x6d\154\137\162\145\161\x75\145\x73\x74\137\163\151\x67\x6e\145\x64");
        if (empty($MB) || $MB == "\110\124\x54\x50\55\122\x65\144\x69\162\x65\x63\x74") {
            goto eR;
        }
        if ($BI) {
            goto T8;
        }
        $ld = base64_encode($Mm);
        Utilities::postSAMLRequest($rK, $ld, $WY);
        exit;
        T8:
        $ld = Utilities::signXML($Mm, Utilities::getPublicCertificate(), Utilities::getPrivateKey(), $dQ, "\116\141\155\145\111\104");
        Utilities::postSAMLRequest($rK, $ld, $WY);
        goto S9;
        eR:
        $Mm = "\x53\x41\115\x4c\x52\145\x71\165\145\x73\164\x3d" . $Mm . "\46\122\x65\154\141\171\123\x74\x61\164\145\75" . urlencode($WY);
        $kX = $rK;
        if (strpos($rK, "\77") !== false) {
            goto cU;
        }
        $kX .= "\77";
        goto RX;
        cU:
        $kX .= "\46";
        RX:
        if (!$BI) {
            goto U9;
        }
        if ($dQ == "\x52\123\x41\x5f\x53\110\101\x32\x35\66") {
            goto Jz;
        }
        if ($dQ == "\122\123\x41\x5f\x53\110\101\x33\70\x34") {
            goto Cb;
        }
        if ($dQ == "\x52\123\x41\137\123\110\101\x35\61\62") {
            goto yR;
        }
        if ($dQ == "\122\123\101\x5f\123\110\101\61") {
            goto p_;
        }
        goto nq;
        Jz:
        $Mm .= "\x26\123\151\147\101\154\x67\75" . urlencode(XMLSecurityKey::RSA_SHA256);
        goto nq;
        Cb:
        $Mm .= "\x26\123\x69\147\101\154\147\75" . urlencode(XMLSecurityKey::RSA_SHA384);
        goto nq;
        yR:
        $Mm .= "\x26\x53\151\x67\x41\154\x67\75" . urlencode(XMLSecurityKey::RSA_SHA512);
        goto nq;
        p_:
        $Mm .= "\46\123\151\147\x41\x6c\x67\x3d" . urlencode(XMLSecurityKey::RSA_SHA1);
        nq:
        $RO = array("\x74\171\160\145" => "\160\162\x69\x76\x61\164\145");
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, $RO);
        if ($dQ == "\122\123\x41\x5f\x53\110\x41\x33\x38\64") {
            goto ED;
        }
        if ($dQ == "\122\x53\101\x5f\123\x48\101\x35\x31\62") {
            goto NA;
        }
        if ($dQ == "\x52\123\101\x5f\123\110\x41\x31") {
            goto XV;
        }
        goto z_;
        ED:
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA384, $RO);
        goto z_;
        NA:
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, $RO);
        goto z_;
        XV:
        $yQ = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, $RO);
        z_:
        $yQ->loadKey(Utilities::getPrivateKey(), FALSE);
        $d0 = new XMLSecurityDSig();
        $Qz = $yQ->signData($Mm);
        $Qz = base64_encode($Qz);
        $kX .= $Mm . "\46\123\151\x67\156\x61\164\165\162\145\x3d" . urlencode($Qz);
        if ($f5->get("\x6d\151\156\x69\x6f\162\141\156\x67\x65\137\x73\141\x6d\x6c\x5f\x73\145\156\x64\137\x73\154\157\137\151\x6e\137\x69\146\x72\x61\x6d\145")) {
            goto EY;
        }
        header("\x4c\x6f\143\141\x74\x69\157\156\x3a\40" . $kX);
        exit;
        goto qM;
        EY:
        echo "\74\x69\146\162\141\x6d\x65\40\x69\144\75\47\155\157\x5f\163\141\x6d\x6c\137\x69\x66\162\141\155\x65\x5f\163\x6c\x6f\47\40\x73\162\143\x3d\x27" . $kX . "\47\x20\163\x74\171\x6c\145\75\47\160\x6f\x73\151\164\151\x6f\x6e\x3a\40\141\142\163\157\x6c\x75\x74\x65\73\40\x68\145\x69\x67\150\164\72\x20\60\73\40\167\151\x64\x74\x68\x3a\40\x30\73\x20\142\x6f\162\144\145\x72\72\x20\x30\x3b\x27\40\x3e\x3c\x2f\x69\146\162\141\155\x65\76";
        exit;
        qM:
        goto sg;
        U9:
        $kX .= $Mm;
        if ($f5->get("\x6d\x69\156\151\157\x72\141\x6e\x67\x65\x5f\x73\x61\155\x6c\137\163\145\156\x64\x5f\x73\x6c\157\137\151\156\137\151\146\162\x61\155\x65")) {
            goto Sk;
        }
        $Yq = new RedirectResponse($kX);
        $Yq->send();
        return new Response();
        goto sQ;
        Sk:
        echo "\x3c\151\x66\x72\x61\x6d\145\40\151\144\75\x27\x6d\157\137\163\141\x6d\x6c\137\151\146\162\141\x6d\x65\137\163\154\x6f\47\40\163\x72\143\x3d\x27" . $kX . "\x27\40\163\164\171\154\x65\75\x27\x70\157\163\x69\164\x69\x6f\156\x3a\40\141\x62\x73\x6f\154\x75\x74\x65\x3b\40\x68\145\x69\x67\150\x74\x3a\40\x30\73\x20\x77\151\144\x74\x68\x3a\40\x30\73\x20\142\x6f\x72\x64\145\162\x3a\40\x30\73\47\40\x3e\x3c\x2f\x69\x66\162\141\155\x65\x3e";
        exit;
        sQ:
        sg:
        S9:
        pE:
        $w7 = \Drupal::request();
        $w7->getSession()->clear();
        if (!($f5->get("\155\x69\156\x69\157\x72\x61\x6e\x67\x65\137\x73\x61\x6d\x6c\137\x73\145\156\x64\137\x73\154\157\x5f\x69\x6e\x5f\x69\x66\162\x61\155\145") && !isset($_GET["\x66\151\156\x61\x6c"]))) {
            goto MP;
        }
        echo "\74\x73\x63\162\x69\x70\164\76\40\167\151\156\144\x6f\x77\56\164\157\x70\x2e\154\157\143\x61\x74\151\x6f\156\x2e\x68\162\x65\146\x20\75\40\47" . $aa . "\x2f\165\163\145\162\x2f\154\157\147\157\x75\x74\77\x66\151\156\x61\x6c\x3d\164\x72\165\x65\47\x3b\40\74\x2f\x73\x63\162\151\160\x74\76";
        exit;
        MP:
        $Yq = new RedirectResponse($pF);
        $Yq->send();
        return new Response();
        goto HF;
        ZA:
        session_start();
        return new Response();
        HF:
        CP:
        return new Response();
    }
    function test_configuration()
    {
        self::saml_login('', "\x74\145\163\x74\x56\x61\154\151\x64\x61\x74\x65");
        return new Response();
    }
    function saml_request()
    {
        $yr = \Drupal::config("\x6d\151\156\x69\157\x72\x61\156\x67\x65\x5f\x73\141\155\154\56\x73\145\x74\x74\151\156\147\x73")->get("\155\x69\156\x69\x6f\x72\x61\156\147\x65\x5f\x73\x61\155\x6c\x5f\x69\x64\160\x5f\154\x6f\x67\151\x6e\137\x75\x72\154");
        $wi = \Drupal::config("\x6d\151\156\x69\157\162\x61\x6e\x67\x65\137\163\141\x6d\154\x2e\x73\145\x74\164\x69\x6e\x67\163")->get("\155\x69\x6e\x69\x6f\162\141\x6e\147\x65\137\163\x61\155\154\137\x6e\141\155\x65\151\x64\x5f\x66\x6f\x72\x6d\x61\x74");
        $Hg = Utilities::createAuthnRequest(Utilities::getAcsUrl(), Utilities::getIssuer(), $wi, $yr, "\110\x54\124\x50\55\x50\117\123\x54", "\x66\141\x6c\163\x65");
        $WY = "\x64\x69\163\x70\x6c\x61\171\x53\x41\115\114\122\145\x71\x75\145\163\x74";
        $BI = \Drupal::config("\x6d\151\x6e\151\x6f\162\x61\x6e\147\x65\x5f\163\141\x6d\x6c\x2e\163\145\x74\x74\151\156\x67\x73")->get("\x6d\151\x6e\151\157\x72\x61\x6e\147\145\137\x73\141\x6d\154\x5f\162\x65\161\165\x65\163\x74\x5f\163\151\x67\x6e\x65\144");
        $dQ = \Drupal::config("\x6d\x69\156\x69\157\162\x61\x6e\x67\145\x5f\163\x61\x6d\154\56\163\145\x74\x74\x69\x6e\x67\163")->get("\163\x65\x63\165\x72\x69\164\x79\x5f\x73\x69\x67\156\141\164\x75\x72\145\137\141\x6c\147\157\x72\x69\x74\150\155");
        if (!$BI) {
            goto Ec;
        }
        $ld = Utilities::signXML($Hg, Utilities::getPublicCertificate(), Utilities::getPrivateKey(), $dQ, "\x4e\x61\155\x65\x49\x44\120\x6f\154\x69\143\171");
        $Hg = base64_decode($ld);
        Ec:
        Utilities::Print_SAML_Request($Hg, $WY);
        return new Response();
    }
    function saml_response_generator()
    {
        self::saml_login('', "\144\151\163\x70\154\x61\171\123\141\155\x6c\x52\145\x73\160\x6f\156\x73\145");
        return new Response();
    }
    public function openModalForm()
    {
        $Yq = new AjaxResponse();
        $Yd = $this->formBuilder->getForm("\134\x44\162\x75\x70\x61\x6c\134\x6d\151\x6e\x69\157\x72\141\156\x67\145\137\x73\x61\x6d\x6c\134\x46\x6f\162\x6d\x5c\115\x69\156\151\157\x72\x61\156\147\145\x53\x41\115\x4c\x52\x65\155\157\166\x65\114\151\x63\x65\156\163\145");
        $Yq->addCommand(new OpenModalDialogCommand("\122\x65\x6d\x6f\x76\145\40\x4c\x69\x63\145\156\163\145\x20\x4b\x65\x79", $Yd, ["\x77\151\x64\164\150" => "\70\x30\60"]));
        return $Yq;
    }
    public static function moLicenseFetch($Ox = "\146\145\164\x63\150\x4c\x69\x63\x65\x6e\163\145\115\x61\x6e\165\x61\x6c\154\x79")
    {
        global $base_url;
        $QB = \Drupal::config("\x6d\151\x6e\151\157\162\x61\x6e\x67\145\x5f\163\x61\x6d\x6c\56\163\145\164\164\x69\156\147\163")->get("\x6d\151\156\x69\157\x72\x61\156\147\145\137\163\x61\x6d\154\x5f\143\165\163\164\x6f\155\145\162\137\141\144\155\151\x6e\x5f\145\x6d\x61\x69\x6c");
        $PV = new MiniorangeSAMLCustomer($QB, NULL, NULL, NULL);
        $Do = $PV->ccl() !== NULL ? json_decode($PV->ccl(), true) : '';
        if (!empty($Do)) {
            goto Lj;
        }
        if ($Ox == "\146\x65\x74\x63\150\x4c\x69\x63\x65\156\x73\145\x4d\x61\156\x75\141\154\154\x79") {
            goto Su;
        }
        \Drupal::logger("\155\151\x6e\x69\x6f\x72\x61\156\147\x65\137\x73\x61\x6d\x6c")->error("\123\157\155\145\164\150\151\x6e\x67\x20\167\x65\x6e\164\40\x77\162\157\x6e\x67\40\x77\150\x69\x6c\145\x20\146\145\x74\143\x68\x69\x6e\x67\x20\x6c\x69\143\145\156\x73\x65\x20\x75\x70\144\141\164\145\40\x69\156\x20" . __FUNCTION__ . "\x20\x28\x6c\151\x6e\145\40" . __LINE__ . "\x20\157\x66\40" . __FILE__ . "\51");
        return;
        goto de;
        Su:
        \Drupal::messenger()->addError(t("\123\x6f\x6d\x65\164\150\151\x6e\147\x20\167\145\x6e\x74\x20\x77\162\157\156\147\40\167\x68\151\x6c\145\x20\146\145\x74\x63\x68\x69\156\147\40\x6c\x69\143\145\x6e\x73\x65\40\x75\x70\x64\x61\164\x65"));
        $Yq = new RedirectResponse($base_url . "\x2f\x61\144\155\x69\x6e\57\x63\157\x6e\146\151\147\57\x70\145\x6f\160\x6c\145\x2f\x6d\151\156\151\157\x72\x61\x6e\147\x65\137\163\141\155\x6c\57\143\x75\x73\x74\x6f\x6d\x65\x72\x5f\x73\x65\164\x75\160");
        return $Yq->send();
        de:
        Lj:
        Utilities::mo_save_expiry_details($Do);
        $l_ = \Drupal::config("\x6d\151\x6e\151\157\162\141\x6e\x67\x65\x5f\163\x61\155\154\56\x73\145\164\164\x69\156\x67\163")->get("\155\151\156\151\157\x72\141\x6e\147\x65\137\x6d\141\x69\156\x74\145\x6e\x61\x6e\x63\x65\137\145\170\x70\x69\x72\171");
        $fi = Utilities::getIsLicenseExpired($l_);
        if (!($fi["\x4c\x69\143\x65\156\x73\145\x41\154\162\145\141\144\171\x45\170\x70\x69\162\x65\144"] == true)) {
            goto s_;
        }
        \Drupal::logger("\155\x69\x6e\151\157\162\141\156\x67\x65\x5f\163\x61\155\154")->error("\x59\157\x75\162\40\x6d\151\156\x69\117\x72\141\x6e\x67\x65\40\x53\101\115\114\40\123\120\40\155\x6f\x64\165\x6c\x65\40\155\x61\151\156\164\x65\156\x61\x6e\x63\x65\40\x68\141\163\40\x65\170\160\x69\x72\x65\144\x2e\x20\124\150\151\163\x20\150\141\163\40\160\162\x65\166\x65\x6e\x74\145\x64\x20\x79\157\x75\40\146\162\157\155\40\162\x65\x63\145\151\166\151\x6e\x67\x20\141\156\x79\x20\155\157\144\x75\x6c\145\x20\165\160\x64\141\x74\145\163\40\143\x6f\x6e\164\141\x69\x6e\x69\x6e\147\40\x62\165\147\x20\146\x69\x78\145\163\54\40\156\x65\x77\40\146\145\x61\x74\x75\162\x65\163\54\x20\x61\156\144\x20\x65\x76\145\x6e\40\x63\157\155\x70\141\164\x69\142\151\154\151\164\x79\x20\143\150\x61\156\x67\x65\163\56\40\120\x6c\145\x61\x73\145\40\x63\157\x6e\164\x61\143\x74\40\x75\x73\x20\157\156\x20\74\141\40\x68\x72\145\x66\40\x3d\42\x64\162\x75\160\141\x6c\163\x75\x70\160\x6f\162\x74\x40\170\x65\143\x75\x72\x69\146\171\56\143\x6f\155\42\x3e\x64\x72\165\160\x61\x6c\x73\165\x70\x70\157\x72\164\x40\170\x65\143\x75\162\x69\146\x79\x2e\x63\157\x6d\x3c\57\x61\x3e\x20\x74\157\x20\x72\x65\156\x65\x77\x20\x79\157\165\x72\40\x6d\x61\x69\x6e\x74\145\156\141\156\x63\145\x2e");
        s_:
        if (!($Ox == "\146\145\x74\143\x68\x4c\x69\143\x65\x6e\x73\x65\115\141\x6e\165\x61\x6c\154\171")) {
            goto pg;
        }
        \Drupal::messenger()->addStatus(t("\123\165\x63\143\145\x73\x73\x66\165\x6c\x6c\x79\40\146\x65\164\x63\150\x65\x64\40\164\150\x65\40\x6c\151\143\x65\156\x73\x65\40\144\145\x74\x61\x69\154\x73"));
        $Yq = new RedirectResponse($base_url . "\x2f\x61\x64\155\x69\156\x2f\143\x6f\x6e\146\151\x67\57\160\x65\x6f\x70\154\145\57\155\151\156\151\157\x72\x61\x6e\x67\x65\x5f\x73\x61\x6d\x6c\x2f\143\x75\163\164\157\155\145\162\x5f\x73\x65\x74\165\160");
        return $Yq->send();
        pg:
    }
    function saml_metadata()
    {
        $f5 = \Drupal::config("\x6d\151\156\151\157\162\x61\156\x67\x65\137\x73\x61\x6d\x6c\56\163\145\164\164\151\x6e\147\x73");
        $aa = Utilities::getBaseUrl();
        $rI = Utilities::getIssuer();
        $se = Utilities::getAcsUrl();
        $l8 = Utilities::getPublicCertificate();
        $fW = preg_replace("\x2f\x5b\xd\12\135\x2b\57", '', $l8);
        $fW = str_replace("\x2d\x2d\x2d\x2d\55\x42\105\107\x49\x4e\40\x43\105\x52\x54\x49\x46\x49\x43\101\x54\x45\x2d\x2d\55\x2d\55", '', $fW);
        $fW = str_replace("\x2d\x2d\x2d\55\55\x45\x4e\x44\40\103\x45\x52\x54\111\106\111\103\x41\x54\x45\x2d\55\x2d\55\x2d", '', $fW);
        $fW = str_replace("\55\55\x2d\x2d\55\x42\x45\107\111\x4e\40\x50\125\x42\114\111\x43\x20\113\105\131\55\x2d\55\x2d\x2d", '', $fW);
        $fW = str_replace("\x2d\55\55\55\x2d\x45\116\104\x20\120\x55\x42\114\111\103\x20\x4b\105\x59\x2d\55\55\55\x2d", '', $fW);
        $fW = str_replace("\40", '', $fW);
        if (isset($_REQUEST["\144\x6f\167\x6e\154\x6f\x61\x64\103\145\x72\x74\151\x66\151\x63\x61\x74\145"]) && $_REQUEST["\144\157\167\156\x6c\157\x61\144\103\x65\x72\164\x69\x66\x69\x63\141\164\x65"] && boolval($_REQUEST["\x64\157\167\x6e\154\x6f\x61\144\x43\x65\x72\x74\x69\x66\151\143\x61\164\x65"])) {
            goto D_;
        }
        if (isset($_REQUEST["\x64\x6f\167\x6e\154\x6f\141\144"]) && $_REQUEST["\144\157\x77\x6e\154\x6f\x61\144"] && boolval($_REQUEST["\x64\x6f\x77\x6e\154\157\x61\144"])) {
            goto eP;
        }
        $I9 = "\103\157\x6e\x74\145\156\164\x2d\124\x79\x70\x65\x3a\x20\164\x65\170\164\57\170\x6d\154";
        goto ug;
        D_:
        $I9 = "\103\157\x6e\164\x65\x6e\x74\55\x44\151\163\160\x6f\x73\x69\164\151\157\156\72\40\141\x74\164\141\x63\x68\x6d\x65\156\164\73\x20\146\x69\154\145\156\x61\155\x65\75\x22\163\160\x2d\x63\x65\162\164\x69\146\x69\143\x61\164\145\x2e\143\162\164\x22";
        header($I9);
        echo xss::filter($l8);
        exit;
        goto ug;
        eP:
        $I9 = "\103\157\x6e\x74\x65\x6e\x74\55\104\151\x73\x70\x6f\x73\x69\x74\151\157\156\x3a\40\x61\x74\164\141\x63\150\x6d\145\156\x74\x3b\x20\x66\x69\x6c\145\x6e\141\x6d\145\75\42\x4d\x65\164\x61\144\x61\x74\141\x2e\x78\x6d\154\x22";
        ug:
        header($I9);
        echo "\x3c\77\x78\155\154\x20\x76\145\x72\x73\x69\157\x6e\75\42\61\x2e\60\x22\x3f\x3e\xa\x20\x20\40\40\40\x20\40\x20\x3c\x6d\x64\x3a\105\x6e\164\151\164\171\x44\145\163\x63\162\151\x70\x74\157\162\x20\170\155\154\x6e\163\x3a\x6d\x64\x3d\x22\x75\162\x6e\72\157\x61\x73\x69\x73\x3a\156\x61\x6d\x65\x73\x3a\164\143\x3a\123\x41\115\x4c\x3a\62\56\x30\72\155\145\164\141\144\x61\164\141\42\40\x76\x61\154\x69\144\125\x6e\x74\x69\154\x3d\42\62\60\x32\x34\x2d\60\x33\55\62\x37\x54\x32\63\x3a\x35\71\72\x35\x39\132\x22\x20\x63\141\143\150\145\104\x75\x72\141\164\151\157\156\75\x22\120\124\61\64\x34\66\x38\60\x38\67\71\62\123\x22\40\145\156\x74\151\x74\171\x49\104\75\42" . $rI . "\x22\x3e\12\40\x20\x20\x20\40\x20\40\40\40\x20\x3c\x6d\x64\x3a\x53\x50\x53\x53\x4f\x44\145\x73\x63\162\151\x70\x74\157\162\x20\101\x75\164\150\x6e\x52\x65\x71\x75\x65\163\164\x73\x53\x69\147\156\145\x64\75\42\164\162\165\x65\x22\x20\127\x61\x6e\164\101\x73\163\145\162\x74\151\157\x6e\163\x53\x69\147\156\145\144\x3d\42\x74\x72\x75\x65\42\x20\160\162\x6f\164\x6f\143\x6f\x6c\123\165\160\160\x6f\162\164\x45\x6e\x75\155\x65\162\x61\164\x69\157\x6e\75\42\165\162\156\72\x6f\141\x73\151\163\72\x6e\141\155\x65\x73\72\x74\143\x3a\x53\x41\x4d\114\72\62\x2e\60\x3a\x70\x72\157\164\157\143\157\154\42\x3e\12\40\x20\40\x20\x20\x20\x20\x20\40\40\x20\40\x3c\x6d\144\x3a\x4b\x65\171\x44\x65\163\143\162\151\160\164\x6f\162\x20\165\x73\145\75\x22\163\x69\147\156\151\156\x67\42\76\12\x20\x20\40\40\x20\x20\40\x20\40\x20\40\x20\40\40\74\144\x73\x3a\x4b\145\x79\x49\156\x66\157\40\170\x6d\x6c\156\163\x3a\x64\163\x3d\x22\150\164\x74\x70\x3a\57\57\167\x77\167\56\167\63\x2e\157\x72\x67\57\62\x30\60\60\x2f\x30\x39\57\170\155\x6c\x64\163\151\147\43\42\76\12\40\x20\40\40\40\x20\40\x20\x20\40\40\x20\40\40\x20\x20\74\x64\x73\x3a\x58\65\60\x39\104\x61\164\141\76\xa\x20\x20\40\40\40\40\40\x20\40\40\x20\x20\x20\40\x20\40\x20\40\74\x64\163\72\x58\65\x30\71\x43\x65\162\164\x69\146\151\143\141\164\145\76" . $fW . "\x3c\57\x64\x73\x3a\130\65\60\71\103\145\x72\164\151\146\x69\x63\141\164\x65\x3e\xa\40\40\x20\40\x20\x20\40\x20\40\40\40\40\40\x20\x20\40\74\57\144\163\x3a\130\65\x30\71\104\x61\164\141\x3e\12\40\x20\40\40\40\40\40\x20\x20\40\x20\40\x20\x20\x3c\x2f\144\163\x3a\113\145\x79\x49\x6e\146\x6f\76\xa\40\x20\x20\x20\40\40\x20\40\x20\x20\40\40\74\57\x6d\144\x3a\x4b\145\171\x44\145\x73\x63\162\151\x70\164\157\x72\76\12\x20\x20\x20\x20\40\40\x20\40\x20\x20\40\40\74\x6d\144\x3a\x4b\x65\171\104\145\x73\x63\162\x69\160\x74\157\162\x20\165\x73\x65\x3d\x22\145\156\x63\162\x79\160\164\x69\x6f\156\42\76\12\x20\40\x20\x20\x20\40\x20\40\40\40\x20\40\40\40\74\144\x73\72\113\145\171\x49\x6e\x66\157\x20\x78\x6d\154\156\163\x3a\x64\163\x3d\42\x68\164\x74\160\x3a\57\x2f\167\167\x77\56\x77\63\x2e\157\x72\147\x2f\x32\60\60\x30\57\x30\x39\57\x78\x6d\x6c\144\x73\151\x67\43\42\76\12\40\40\x20\40\x20\40\x20\x20\x20\x20\x20\x20\x20\40\40\x20\74\x64\x73\72\x58\x35\60\x39\104\x61\x74\141\x3e\12\40\40\x20\40\40\x20\x20\x20\x20\40\x20\x20\x20\x20\x20\40\x20\x20\74\144\163\72\130\x35\60\x39\103\145\x72\164\x69\x66\151\143\x61\164\x65\76" . $fW . "\x3c\x2f\144\163\x3a\130\x35\60\x39\x43\x65\x72\164\151\146\151\x63\x61\164\x65\x3e\xa\40\x20\40\40\40\x20\x20\40\x20\x20\x20\x20\40\x20\x20\40\x3c\x2f\144\x73\x3a\130\65\60\71\104\141\x74\x61\x3e\xa\40\x20\x20\x20\40\40\x20\x20\x20\40\x20\40\x20\x20\x3c\57\x64\163\x3a\x4b\x65\x79\x49\156\146\x6f\76\xa\40\40\x20\x20\40\40\40\x20\x20\40\40\40\74\57\x6d\144\72\113\145\171\104\x65\163\143\x72\x69\160\x74\157\162\76\xa\40\40\x20\x20\40\40\x20\40\x20\40\x20\40\74\155\x64\72\x53\x69\x6e\x67\x6c\x65\114\x6f\147\x6f\x75\x74\x53\x65\x72\166\x69\143\x65\40\102\151\156\x64\x69\156\x67\75\x22\x75\162\x6e\x3a\x6f\x61\x73\151\x73\x3a\x6e\141\155\x65\163\x3a\164\143\72\123\x41\x4d\114\72\x32\56\x30\72\142\151\156\144\x69\x6e\x67\163\x3a\110\124\x54\x50\55\120\117\x53\124\x22\x20\x4c\157\x63\141\164\x69\x6f\156\x3d\x22" . $aa . "\57\x75\x73\x65\162\x2f\x6c\x6f\x67\157\x75\x74\42\57\x3e\12\x20\40\x20\x20\40\x20\40\x20\40\x20\x20\40\74\155\x64\x3a\123\x69\x6e\x67\x6c\145\114\x6f\x67\157\x75\164\x53\145\x72\x76\x69\143\145\40\102\x69\156\144\x69\156\147\x3d\x22\x75\x72\156\72\157\141\163\x69\x73\x3a\x6e\x61\155\145\163\x3a\x74\143\72\123\101\x4d\114\x3a\62\x2e\60\x3a\x62\151\x6e\x64\x69\156\147\x73\x3a\x48\x54\124\x50\55\x52\145\x64\x69\x72\x65\143\164\42\x20\114\157\143\141\164\151\157\156\75\x22" . $aa . "\57\x75\x73\145\162\x2f\x6c\x6f\x67\x6f\165\x74\x22\x2f\x3e\xa\40\40\40\x20\x20\x20\40\40\40\x20\x20\40\x3c\155\x64\x3a\116\141\x6d\145\111\104\106\157\162\x6d\141\x74\x3e\x75\x72\156\x3a\x6f\141\x73\151\x73\72\x6e\x61\x6d\145\163\x3a\x74\x63\72\x53\x41\x4d\x4c\72\x31\x2e\61\x3a\156\141\x6d\145\x69\x64\x2d\x66\157\x72\x6d\x61\164\x3a\145\155\141\x69\x6c\x41\144\x64\x72\145\163\x73\x3c\57\x6d\x64\72\116\x61\x6d\x65\111\104\x46\157\x72\155\x61\x74\x3e\12\40\40\x20\x20\x20\x20\x20\x20\40\40\40\x20\74\x6d\x64\72\x4e\141\x6d\x65\x49\x44\x46\x6f\162\x6d\141\164\x3e\165\x72\156\72\x6f\141\163\x69\163\72\x6e\x61\155\145\x73\x3a\x74\143\72\x53\x41\x4d\114\72\62\x2e\60\x3a\x6e\x61\x6d\145\x69\x64\55\146\157\162\x6d\x61\164\x3a\165\x6e\x73\x70\x65\x63\x69\146\x69\x65\144\74\57\x6d\144\x3a\x4e\141\x6d\x65\x49\x44\106\x6f\x72\x6d\141\164\x3e\xa\40\x20\x20\40\40\x20\40\x20\40\x20\40\40\x3c\155\x64\72\x4e\141\x6d\145\x49\x44\106\x6f\162\155\x61\x74\x3e\x75\162\156\x3a\x6f\x61\163\x69\163\72\x6e\141\155\x65\x73\72\164\143\72\123\101\x4d\x4c\x3a\62\56\x30\72\156\x61\x6d\x65\151\144\x2d\x66\x6f\x72\x6d\x61\x74\72\164\162\141\156\x73\151\x65\156\x74\74\57\x6d\144\72\116\141\155\145\x49\x44\106\157\x72\155\x61\x74\x3e\12\x20\40\40\40\x20\40\x20\40\40\x20\40\40\x3c\x6d\144\x3a\101\x73\x73\145\x72\x74\151\157\156\103\x6f\156\x73\x75\x6d\145\162\123\x65\162\x76\x69\x63\x65\40\x42\x69\x6e\144\151\x6e\x67\x3d\x22\x75\162\156\x3a\157\x61\163\151\163\x3a\156\x61\x6d\145\x73\72\x74\x63\x3a\x53\x41\115\114\72\x32\56\x30\x3a\142\x69\156\144\151\x6e\x67\x73\x3a\x48\x54\x54\x50\55\120\117\123\124\42\40\x4c\157\x63\141\164\151\x6f\x6e\x3d\x22" . $se . "\42\x20\151\x6e\144\145\170\x3d\42\61\42\57\x3e\12\40\x20\x20\40\40\40\40\x20\40\40\x3c\x2f\155\x64\72\x53\x50\123\x53\x4f\x44\x65\163\x63\x72\151\160\164\157\x72\x3e\12\40\x20\x20\x20\40\x20\x20\40\x20\x20\74\155\144\x3a\117\x72\x67\141\x6e\151\x7a\141\x74\x69\x6f\x6e\x3e\xa\x20\40\x20\40\40\40\x20\x20\40\40\40\x20\x3c\x6d\x64\x3a\117\x72\x67\x61\156\151\172\x61\x74\x69\x6f\156\116\141\155\x65\40\x78\155\x6c\72\154\x61\156\147\x3d\42\x65\x6e\55\x55\123\42\x3e" . $f5->get("\x6d\x6f\x5f\x73\141\155\x6c\x5f\x6d\145\x74\x61\x64\x61\164\x61\137\x4f\162\x67\141\x6e\x69\172\141\164\x69\x6f\156\116\141\x6d\145") . "\x3c\57\x6d\144\x3a\x4f\x72\147\141\156\x69\172\141\164\151\x6f\x6e\116\141\x6d\145\76\12\x20\x20\40\x20\40\x20\x20\40\x20\x20\x20\40\74\155\144\72\x4f\162\147\x61\156\151\172\x61\164\x69\157\x6e\x44\x69\x73\160\154\141\x79\x4e\x61\x6d\145\x20\170\x6d\x6c\x3a\x6c\141\x6e\147\75\x22\145\x6e\55\x55\x53\42\76" . $f5->get("\155\157\137\x73\x61\x6d\154\x5f\117\x72\x67\x61\x6e\151\x7a\141\x74\x69\157\x6e\x44\151\x73\160\x6c\x61\x79\x4e\141\x6d\x65") . "\x3c\x2f\x6d\x64\x3a\117\162\147\141\156\x69\x7a\x61\x74\151\157\156\x44\x69\x73\x70\154\x61\x79\x4e\x61\155\145\x3e\xa\40\x20\40\x20\x20\40\x20\40\x20\x20\x20\x20\x3c\155\144\72\x4f\162\147\x61\x6e\x69\x7a\x61\164\151\157\x6e\x55\x52\114\40\x78\x6d\x6c\x3a\x6c\x61\156\x67\75\x22\x65\156\55\125\x53\42\76" . $f5->get("\155\157\137\163\x61\155\x6c\137\117\x72\147\141\156\x69\172\141\x74\x69\157\x6e\125\122\114") . "\x3c\x2f\155\x64\72\x4f\x72\x67\x61\156\151\172\141\164\151\x6f\x6e\125\x52\114\x3e\12\40\x20\40\40\40\x20\40\x20\40\40\74\x2f\155\x64\72\117\162\147\x61\x6e\151\172\x61\x74\x69\157\x6e\x3e\12\40\x20\x20\x20\40\x20\x20\x20\x20\x20\x3c\x6d\x64\x3a\103\x6f\x6e\164\141\x63\164\x50\x65\162\163\x6f\156\40\143\x6f\x6e\x74\141\x63\x74\124\171\160\x65\x3d\x22\164\x65\x63\150\156\151\x63\141\154\42\x3e\xa\x20\40\40\x20\40\x20\40\x20\x20\x20\x20\40\74\x6d\144\72\x47\151\166\x65\156\x4e\x61\155\145\x3e" . $f5->get("\x6d\157\x5f\x73\141\155\x6c\137\103\x6f\156\164\141\x63\x74\120\x65\x72\x73\x6f\x6e\x54\x65\143\150\156\151\x63\141\x6c\x4e\141\155\145") . "\74\57\155\x64\x3a\x47\151\166\x65\x6e\116\141\x6d\x65\x3e\12\x20\40\x20\x20\40\40\40\40\40\x20\40\x20\74\155\144\72\x45\x6d\141\151\x6c\x41\144\144\x72\145\x73\x73\76" . $f5->get("\x6d\x6f\137\163\x61\x6d\154\137\x43\157\x6e\x74\141\x63\164\120\x65\162\163\157\156\x54\145\x63\150\x6e\151\143\x61\x6c\x45\x6d\141\x69\154") . "\x3c\57\155\144\x3a\x45\155\141\151\154\101\x64\x64\162\145\x73\x73\x3e\12\x20\40\x20\40\40\40\40\x20\40\x20\x3c\57\155\144\x3a\x43\157\156\x74\141\143\164\x50\x65\162\x73\157\156\x3e\12\40\40\40\40\x20\x20\x20\x20\x20\x20\74\155\144\x3a\103\157\x6e\164\141\143\x74\x50\x65\x72\x73\x6f\x6e\x20\x63\157\156\164\141\x63\164\x54\x79\160\x65\75\x22\163\x75\x70\160\x6f\x72\164\42\x3e\12\x20\x20\40\40\x20\40\40\x20\40\40\40\40\x3c\155\144\x3a\x47\151\x76\145\x6e\116\x61\155\145\x3e" . $f5->get("\155\157\x5f\x73\x61\x6d\154\137\103\x6f\156\x74\141\143\164\120\x65\x72\163\x6f\x6e\123\165\160\160\157\162\164\x4e\141\x6d\145") . "\x3c\x2f\155\144\x3a\x47\151\x76\145\x6e\116\x61\x6d\x65\76\xa\x20\x20\40\40\40\x20\40\x20\40\40\x20\40\74\x6d\x64\x3a\x45\x6d\141\x69\154\101\144\x64\x72\x65\x73\x73\x3e" . $f5->get("\155\157\x5f\x73\141\155\x6c\137\x43\x6f\156\x74\141\143\x74\120\145\x72\163\157\156\x53\165\x70\x70\x6f\x72\x74\x45\155\141\151\x6c") . "\74\57\x6d\144\72\105\x6d\141\x69\x6c\101\144\144\x72\145\163\163\76\12\x20\40\x20\40\x20\x20\x20\40\x20\x20\x3c\x2f\x6d\144\72\x43\x6f\156\164\141\x63\x74\x50\x65\x72\163\157\156\x3e\12\x20\40\x20\40\x20\40\40\40\74\57\155\x64\72\x45\156\x74\x69\164\171\104\145\163\x63\x72\x69\x70\x74\x6f\x72\76";
        exit;
    }
    public static function isBooleanField($kT)
    {
        $td = FieldStorageConfig::loadByName("\165\x73\x65\x72", $kT);
        $rp = $td->getType();
        if (!($rp == "\x62\x6f\157\154\x65\141\x6e")) {
            goto UD;
        }
        return TRUE;
        UD:
        return FALSE;
    }
}
