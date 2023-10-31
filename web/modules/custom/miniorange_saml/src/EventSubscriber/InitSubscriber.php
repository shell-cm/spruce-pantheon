<?php


namespace Drupal\miniorange_saml\EventSubscriber;

use Drupal\miniorange_saml\Controller\miniorange_samlController;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Drupal\user\Entity\User;
class InitSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents()
    {
        return [KernelEvents::REQUEST => ["\x6f\x6e\105\x76\x65\156\164", 0]];
    }
    public function onEvent()
    {
        global $base_url;
        $Qd = '';
        $f5 = \Drupal::config("\x6d\151\156\151\x6f\x72\x61\x6e\x67\x65\137\x73\x61\x6d\154\56\x73\x65\164\x74\x69\156\147\x73");
        $Gy = $f5->get("\x6d\x69\156\x69\157\x72\141\x6e\147\145\x5f\163\141\x6d\x6c\137\146\157\162\143\x65\x5f\141\x75\164\x68");
        $lz = $f5->get("\155\x69\x6e\x69\157\162\x61\156\x67\145\137\163\x61\x6d\154\x5f\x65\156\x61\142\154\145\x5f\x6c\x6f\x67\x69\x6e");
        $Mx = $f5->get("\155\151\x6e\151\x6f\x72\141\156\147\x65\x5f\163\141\155\x6c\x5f\145\x6e\x61\x62\x6c\145\137\x62\x61\143\153\144\157\157\162");
        $iv = $f5->get("\x6d\x69\156\x69\157\162\141\x6e\x67\x65\137\163\x61\155\154\x5f\x6c\151\143\145\156\163\145\137\x6b\145\171");
        $ty = $f5->get("\155\x69\156\x69\x6f\x72\141\156\147\145\x5f\x62\x61\143\153\144\x6f\157\x72\x5f\161\165\x65\x72\x79");
        if (!$lz) {
            goto hJ;
        }
        if ($Mx && isset($_GET["\x73\x61\x6d\x6c\137\154\x6f\147\151\x6e"]) && $_GET["\x73\141\155\154\x5f\154\x6f\147\151\156"] == $ty) {
            goto At;
        }
        if (!($Gy && !\Drupal::currentUser()->isAuthenticated() && !isset($_REQUEST["\x53\x41\115\x4c\122\145\163\160\157\x6e\163\145"]) && !isset($_POST["\x70\141\x73\x73"]))) {
            goto py;
        }
        $sc = \Drupal::request()->getUri();
        if (isset($_SERVER["\x48\x54\124\120\123"]) && $_SERVER["\110\x54\124\x50\x53"] === "\x6f\156") {
            goto KB;
        }
        $Ay = "\150\164\164\x70";
        goto Hi;
        KB:
        $Ay = "\150\x74\164\x70\x73";
        Hi:
        $Ay .= "\72\57\x2f" . $_SERVER["\110\x54\x54\x50\137\110\117\x53\124"] . "\57\x73\x63\151\155";
        if (!(strpos($sc, $Ay) === FALSE)) {
            goto w6;
        }
        miniorange_samlController::saml_login($sc);
        w6:
        py:
        goto Zh;
        At:
        Zh:
        if (!($iv == NULL)) {
            goto j2;
        }
        $sV = \Drupal::configFactory()->getEditable("\155\151\156\151\x6f\x72\141\x6e\x67\145\x5f\x73\141\x6d\x6c\56\x73\x65\164\x74\x69\156\147\x73");
        $sV->clear("\155\x69\156\151\x6f\162\x61\156\147\145\137\163\x61\155\x6c\137\145\x6e\141\x62\154\145\137\x6c\157\147\x69\x6e")->save();
        $sV->clear("\x6d\151\x6e\x69\x6f\162\141\x6e\147\145\x5f\x73\x61\155\154\137\x66\x6f\162\143\x65\x5f\141\x75\x74\x68")->save();
        $sV->clear("\155\151\x6e\151\157\x72\141\x6e\147\145\x5f\x73\141\x6d\154\137\145\x6e\x61\142\154\145\x5f\142\x61\x63\x6b\144\x6f\x6f\162")->save();
        j2:
        hJ:
    }
}
