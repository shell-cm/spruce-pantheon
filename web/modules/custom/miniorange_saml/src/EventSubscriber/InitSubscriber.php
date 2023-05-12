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
        return [KernelEvents::REQUEST => ["\x6f\156\105\x76\x65\156\x74", 0]];
    }
    public function onEvent()
    {
        global $base_url;
        $Pu = '';
        $y8 = \Drupal::config("\x6d\x69\x6e\151\x6f\x72\141\x6e\x67\x65\137\163\x61\155\x6c\x2e\x73\x65\164\164\151\156\147\x73");
        $h0 = $y8->get("\x6d\x69\x6e\151\157\x72\141\x6e\147\x65\x5f\163\141\x6d\x6c\137\146\157\x72\143\145\137\x61\x75\164\150");
        $S5 = $y8->get("\x6d\x69\156\x69\x6f\x72\141\156\147\145\x5f\x73\x61\155\154\137\x65\156\141\x62\x6c\x65\137\x6c\x6f\x67\x69\156");
        $AI = $y8->get("\155\x69\x6e\x69\157\162\141\156\147\x65\x5f\x73\141\155\x6c\x5f\145\156\141\x62\154\145\x5f\142\141\x63\153\x64\157\157\162");
        $I_ = $y8->get("\155\x69\156\151\x6f\162\141\x6e\147\x65\x5f\163\141\x6d\x6c\137\154\151\143\145\156\x73\145\137\153\145\171");
        $D5 = $y8->get("\155\x69\156\x69\x6f\162\141\x6e\147\145\137\x62\141\143\x6b\x64\x6f\157\162\137\x71\165\145\x72\171");
        if (!$S5) {
            goto U5;
        }
        if ($AI && isset($_GET["\x73\141\x6d\154\137\154\157\147\151\x6e"]) && $_GET["\163\141\x6d\154\x5f\154\x6f\147\x69\x6e"] == $D5) {
            goto vu;
        }
        if (!($h0 && !\Drupal::currentUser()->isAuthenticated() && !isset($_REQUEST["\x53\x41\115\114\x52\145\163\x70\157\156\163\x65"]) && !isset($_POST["\160\141\163\x73"]))) {
            goto M2;
        }
        $nD = \Drupal::request()->getUri();
        miniorange_samlController::saml_login($nD);
        M2:
        goto Ah;
        vu:
        Ah:
        if (!($I_ == NULL)) {
            goto ZP;
        }
        $d6 = \Drupal::configFactory()->getEditable("\x6d\x69\156\151\157\162\x61\156\147\145\137\163\141\155\x6c\x2e\163\145\164\x74\x69\156\x67\x73");
        $d6->clear("\x6d\x69\156\x69\157\162\141\156\x67\145\x5f\163\x61\155\154\137\x65\156\x61\x62\154\x65\137\x6c\x6f\x67\151\x6e")->save();
        $d6->clear("\x6d\x69\x6e\x69\157\162\141\156\147\x65\137\163\141\x6d\154\137\x66\x6f\162\143\145\137\141\x75\x74\150")->save();
        $d6->clear("\x6d\151\x6e\151\x6f\x72\141\156\x67\145\x5f\x73\x61\155\154\137\x65\x6e\141\142\x6c\145\x5f\x62\x61\x63\x6b\144\157\x6f\x72")->save();
        ZP:
        U5:
    }
}
