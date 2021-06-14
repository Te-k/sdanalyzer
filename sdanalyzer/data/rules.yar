rule droidwatcher {
    meta:
        description = "Droid Watcher https://github.com/Odrin/Droid-Watcher/tree/master/DroidWatcher/src/com/droidwatcher"
    strings:
        $str1 = "[front_camera]" ascii
        $str2 = "busybox chmod 644" ascii
        $str3 = "[photo]" ascii
        $str4 = "[record]" ascii
        $str5 = "[call]" ascii
        $str6 = "DW_RECORDED_WAKELOCK" ascii
        $str7 = "[screenshot]" ascii
        $str8 = "screenshot.jpg" ascii
        $str9 = "action_dw_update" ascii
        $str10 = "update.apk" ascii
        $str11 = "/data/data/com.viber.voip/databases/viber_messages" ascii
        $str12 = "viber_messages" ascii
        $str13 = "chmod 777 /data/data/com.viber.voip/databases/*" ascii
        $str14 = "com.viber.voip" ascii
        $str15 = "VK_ENABLED" ascii
        $str16 = "[WhatsAppModule] Start watching" ascii
        $str17 = "[AppService] starting service" ascii
        $str18 = "[AppService] Root available" ascii
        $str19 = "[AppService] Low memory" ascii
        $str20 = "DW_WIFILOCK" ascii
        $str21 = "[FileSender (" ascii
        $str22 = "APP_RUN_CODE" ascii
        $str23 = "SCREENSHOT_PHOTO_FORMAT" ascii
        $str24 = "DW_SMS_SENT" ascii

    condition:
        uint16(0) == 0x6564 and 20 of them
}

rule adobot {
    meta:
        desc = "adobot"
        url = "https://github.com/adonespitogo/AdoBot"

    strings:
        $a = "Sms saved!!! From: " ascii
        $b = "/call-logs" ascii
        $c = "Invoking Call LOg Service" ascii
        $d = "Invoking GetContactsTask" ascii
        $e = "Invoking SendSMS" ascii
        $f = "Invoking Transfer bot command" ascii
        $g = "no root, open update activity" ascii
        $h = "Ping call back!!! Status code:" ascii
        $i = "Sms failed to submit!!!" ascii
        $j = "Location changed ...." ascii

    condition:
        uint16(0) == 0x6564 and 8 of them
}
