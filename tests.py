import unittest
from vigenere import VigenereBreaker

# https://asecuritysite.com/encryption/ic?val1=UIF%20IFBSUCMFFE%20CVH%20IBT%20UVSOFE%20DZCFS%20DSJNJOBMT%20GSPN%20BUUBDLFST%20JOUP%20WJDUJNT%20BT%20SFTFBSDIFST%20VTF%20JU%20UP%20HSBC%20NBUFSJBM%20GSPN%20DIBUSPPNT%20XIFSF%20UIFZ%20USBEF%20EBUB.%20EJTDPWFSFE%20JO%20FBSMZ%20BQSJM%2C%20IFBSUCMFFE%20MFUT%20BUUBDLFST%20TUFBM%20EBUB%20GSPN%20DPNQVUFST%20VTJOH%20WVMOFSBCMF%20WFSTJPOT%20PG%20TPNF%20XJEFMZ%20VTFE%20TFDVSJUZ%20QSPHSBNT.%20OPX%20JU%20IBT%20HJWFO%20BOUJ-NBMXBSF%20SFTFBSDIFST%20BDDFTT%20UP%20GPSVNT%20UIBU%20XPVME%20PUIFSXJTF%20CF%20WFSZ%20IBSE%20UP%20QFOFUSBUF.%20UIF%20OFXT%20DPNFT%20BT%20PUIFST%20XBSO%20UIBU%20UIF%20CVH%20XJMM%20CF%20B%20UISFBU%20GPS%20NBOZ%20ZFBST.%20GSFODI%20BOUJ-NBMXBSF%20SFTFBSDIFS%20TUFWFO%20L%20UPME%20UIF%20CCD%3A%20UIF%20QPUFOUJBM%20PG%20UIJT%20WVMOFSBCJMJUZ%20BGGFDUJOH%20CMBDL-IBU%20TFSWJDFT%20(XIFSF%20IBDLFST%20VTF%20UIFJS%20TLJMMT%20GPS%20DSJNJOBM%20FOET)%20JT%20KVTU%20FOPSNPVT.%20IFBSUCMFFE%20IBE%20QVU%20NBOZ%20TVDI%20GPSVNT%20JO%20B%20DSJUJDBM%20QPTJUJPO%2C%20IF%20TBJE%2C%20MFBWJOH%20UIFN%20WVMOFSBCMF%20UP%20BUUBDL%20VTJOH%20UPPMT%20UIBU%20FYQMPJU%20UIF%20CVH.
# Testes baseados no link acima


class TestVigenereBreakerEnglish(unittest.TestCase):
    vb = VigenereBreaker()

    def testIC1(self):
        cipher = "UIF IFBSUCMFFE CVH IBT UVSOFE DZCFS DSJNJOBMT GSPN BUUBDLFST JOUP WJDUJNT BT SFTFBSDIFST VTF JU UP HSBC NBUFSJBM GSPN DIBUSPPNT XIFSF UIFZ USBEF EBUB. EJTDPWFSFE JO FBSMZ BQSJM, IFBSUCMFFE MFUT BUUBDLFST TUFBM EBUB GSPN DPNQVUFST VTJOH WVMOFSBCMF WFSTJPOT PG TPNF XJEFMZ VTFE TFDVSJUZ QSPHSBNT. OPX JU IBT HJWFO BOUJ-NBMXBSF SFTFBSDIFST BDDFTT UP GPSVNT UIBU XPVME PUIFSXJTF CF WFSZ IBSE UP QFOFUSBUF. UIF OFXT DPNFT BT PUIFST XBSO UIBU UIF CVH XJMM CF B UISFBU GPS NBOZ ZFBST. GSFODI BOUJ-NBMXBSF SFTFBSDIFS TUFWFO L UPME UIF CCD: UIF QPUFOUJBM PG UIJT WVMOFSBCJMJUZ BGGFDUJOH CMBDL-IBU TFSWJDFT (XIFSF IBDLFST VTF UIFJS TLJMMT GPS DSJNJOBM FOET) JT KVTU FOPSNPVT. IFBSUCMFFE IBE QVU NBOZ TVDI GPSVNT JO B DSJUJDBM QPTJUJPO, IF TBJE, MFBWJOH UIFN WVMOFSBCMF UP BUUBDL VTJOH UPPMT UIBU FYQMPJU UIF CVH."
        cipher = self.vb.manipulateCipher(cipher)
        IC = 0.0667446018429377
        key = "b"
        predictedKeyLength = 1

        self.assertAlmostEqual(self.vb.indexOfCoincidence(cipher), IC)

    def testIC2(self):
        cipher = "UJF IGBTUDMGFF DVI JBU VVTOGE DACGS DTJOJPBNT GTPO CUVBELGSU KOVP WKDVJOT BU TFUFCSEIGSU WTG KU UQ ISCC NCUGSKBN HSQN DJBVSQPOT XJFTF UJFA VSCEG FBVB. FJUDQWGSGE JP GBTMA CQTJN, IGBTUDMGFF NFVT BVUCDMFTT TVFCM ECUC HSQN DQNRVVFTT VUJPH WWMPFTBDMG XFTTKPPT PH UPOF XKEGMA WTGE TGDWSKUA RSQHTBOT. PPY KU ICT HKWGO BPUK-OBNXCSG TFUFCSEIGSU CDEFUT UQ HPTVOT UJBV YPWMF QUJFTXKTG DF WGSA JBTE UQ RFPFVSCUG. UJF OGXU EPOFU CT PVIGSU YBTO UJBV VIG DVI YJNM CG C VITFCU GQS NCOA AFCSU. GTFPDJ COVJ-NCMYBTF SGTGBTDJFT UUGWGO L UQMF VIG DCE: UJF QQUGOVJCM PH VIKT WWMPFTBDJNJVZ BHGGDVJPH CNBEL-ICU TGSXJEFU (XJFTF ICDMFTT VUF UJFKS TMJNMU HPT ESKNKOCM FPEU) JU LVUU FPPTNQVU. IGBTUDMGFF JBF RVV OBPZ TWDJ HPTVOT JP C ESKUKDCM QQTKUKPP, IG UBKE, NFCWKOI VIGN WWMPFTBDMG VP BVUCDM WTKOI VPQMU VICU FZQNPKU UJF CWH."
        cipher = self.vb.manipulateCipher(cipher)
        IC = 0.0525191399624077
        key = "bc"
        predictedKeyLength = 2

        self.assertAlmostEqual(self.vb.indexOfCoincidence(cipher), IC)

    def testIC3(self):
        cipher = "UJH JHBTWCNHFF CWJ JDT WVTQFF DAEFT DTLNKQBNV HUPO BVWBENFTV KQUQ WKFUKPT DT UFUHBTFIGUT XTG JV UQ HTDC PBVHSKDM ISQP EKBVUPQPT ZIGUF WIGB VUBFH FDUC. FLTERWGUFF JP FCUMA BRUJN, JHBTWCNHFF MGWT DUVDDMHSU TVHBN ECWB ISQP ERNRXUGUT XTKQH YVNQFTDCNH XHSULPPV QI URNG XKGFNB WVFF TGFVTLUA QTRHTDNU. PRX LU KBU HKYFP BPWJ-PBNZBTH THTGDSEKFTV CFDGVT WP IPTXNU UJDU ZPWOE RUJHSYLTG CG WGUZ KBTG VR RHOGWSCWF. UJH PHXU DQPFU BU PVKFTV YDSP UJDU WIG CWJ YLMN CG B WITHBV GQU ODOA ZGDSU. HUFPFI DOVL-ODMYDSG SGVFCUDJHS VUGYFP L WPNG VKF ECE: VKF SPVHOVLBN PH UJLT YVNQFTDCKOJVB CIGGFUKQH EMCFL-KBV TGUWKFFU (YKFTH JDDMHSU VUH VKFKU UNJNOT IPT DTLNKQBN FPGT) JU KWVU HOQUNQXT. IGDSVEMGHE KBF QWW ODOA TWFI IPTXNU JP B FSKWJEDM SPULUKRO, IG TCLE, MGDWKQH WIGP XXMPHSCEMG UQ BVWBEN WVJPJ VRPNV VKBV FZSMQLU WIG CWJ."
        cipher = self.vb.manipulateCipher(cipher)
        IC = 0.0473570806399853
        key = "bcd"
        predictedKeyLength = 3

        self.assertAlmostEqual(self.vb.indexOfCoincidence(cipher), IC)

    def testIC4(self):
        cipher = "UJH IGDVUDOIFF FVI LBU XVTQIE FCCGU DTLQJPDPT IVPO EUVDGLGUW KQXP YMDVLQT DW THWFCUGIGUW WVI KW UQ KSCE NCWISKDP HUSN FLBVUSPOV XJHVF WLFA XSCGI FDXB. HJUFSWGUIE LR GDVMA EQTLP, KIBTWFMGHH NHXT DXUCFOFTV TVHEM GEUC JSQP DQPTVVHVT XWJPJ WWORFTDFMG ZFTVMPPV PH WPOH XKGIMA YTGG TGFYSKWC RUSHTDQT. RPY MU KET JMWGQ BPWM-ODPXCUI THWFCUGIGUW CFGFUV UQ JPTXQT WLBV APWOH QWLFTZMTG FF YISA LBTG UQ TFPHXSCWI. WLF QIXU GPOHW CV PVKISU ABTQ UJDX VKI DXK YLPM EI C XITHEU ISS PEOA CFCUW. IVFPFL CQXJ-PEMYDVF UITGDVDJHV UWIWGQ L WSMF XIG FCE: UJH QQWIOVLEM RJ VKMT YYMPHVBDLPJVB BHIIDVLRH EPBEN-ICW TGUZJEHW (ZLFTH ICFOFTV VUH UJHMS VOJNOW HRV EUMNKQEM HREU) JU NVUW FPRVNQXW. KIBTWFMGHH JDH RXX ODRZ VYDJ JPTXQT LR C GSKWMDCO QQVMUKRR, KI UDME, PFCYMOI XIGP WWORFTDFMG XP DXUCFO WVMOI XPQOW VKEU HBQNRMU WLF EYH."
        cipher = self.vb.manipulateCipher(cipher)
        IC = 0.0442809333883464
        key = "bcde"
        predictedKeyLength = 5

        self.assertAlmostEqual(self.vb.indexOfCoincidence(cipher), IC)

    def testIC5(self):
        cipher = "UJH MFCUXGMGHH CWJ MBU XZSPHH DAEIW EUMRJPDPX HUSR CWXFDMHVX KQXT XLGYJOV FT UIXFCUGMFTV ZTG MY VR LSCE RBVHVNBN JWPO GMBVUSTNU AMFTH YIGB YSCGI ECWE. FLWHPXHVJE LR FCUPD CSVNM, LJBTWFQFGG QFVV FUVDGPFTV XUGDP ECWE GTRQ DQPTZUGUW VULRL XXPSFTDFQF YIWTKRRX QI XPOH BJFHPD WVII UHGZSKWC QTRKWBOV. OQZ NU KEX ILZJO DRYJ-PEQXCUI SGVIFSEKIWT DGHFUV YP ISWVOV YICW BPWOH PVKIWXKVI CG ZJSA LFSF XT RHRJUTDXJ. WLJ PHAX ERQJT DW PVKIWT ZEWO WLFU WLJ DXK XKOP CG E UJUIFU ISW ODRD AHEWT. JWFPFL BPWM-NCOAFSG VJTGDVHIGU XUGYIS M XTMF XMF EFH: WLJ RRXJOVLEQ QI YIKV AVNQIWBDLPNUA EKGGFXNOI FQBEN-MBV WJSXLGJT (AMFTH MBENIWT XWJ VKINS VONMNV KPT GWJOLRFM HRIT) MX LXWY GQSWNQXW. JHEWUDOIJE KEI RXX NCQC TWFL GQUYRT LR B FVNUKFEQ RRWNUKRR, JH XBKG, MGDZNOI XMFO ZZMPHVFCNH YP DXYBEN ZTKQK UQRPX VKEY GATQPKW YIG FZH."
        cipher = self.vb.manipulateCipher(cipher)
        IC = 0.0407004997020126
        key = "bcdef"
        predictedKeyLength = 10

        self.assertAlmostEqual(self.vb.indexOfCoincidence(cipher), IC)

    def testIC6(self):
        cipher = "UJH MKBTWFQKFF FZM JDW ZVTQII DAEIW DTLQNTBNV KXPO EYZBENIWY KQXT WKFXNST DW XFUHEWIIGUW ATG MY UQ KWGC PEYKSKDP LSQP HNBVUSTST ZLJXF WLJE VUEIK FDXF. FLWHUWGUII JP IFXMA EUXJN, MKBTWFQKFF PJZT DXYGDMHVX TVHEQ ECWE LSQP HUNRXXJXT XWNTH YYQTFTDFQK XHVXOPPV TL URQJ XKGIQE WVII TGFYWOUA TWUHTDQX. PRA OU KEX HKYIS BPWM-SBNZEWK THWJGSEKIWY CFGJYT WS LPTXQX UJDX CPWOH UUJHVBOTG FJ WGUC NBTG YU RHRJZSCWI. UJH SKXU GTSFU EX PVKIWY YDVS UJDX ZIG FZM YLPQ CG E ZITHEY GQU RGOA CJGSU. KXFPFL GOVL-RGMYDVJ SGVIFXDJHV YUGYIS L WSQJ VKI HCE: YNF SSYKOVLEQ PH XMOT YYQTFTDFNRJVB FLGGFXNTH EPFIL-KEY TGUZNIFU (BNFTH MGDMHVX VUH YNFKU XQJNOW LPT GWONKQEQ FPGW) JU NZYU HRTXNQXW. IGDVYHMGHH NBF TZZ ODRD TWFL LPTXQX JP E ISKWMHGM SSXOUKRR, IG WFOE, PJGWKQK ZIGP AAMPHVFHMG XT BVWEHQ WVMSM VRSQY VKEY FZSPTOU WLJ CWJ."
        cipher = self.vb.manipulateCipher(cipher)
        IC = 0.0419795534772842
        key = "bcdefg"
        predictedKeyLength = 7

        self.assertAlmostEqual(self.vb.indexOfCoincidence(cipher), IC)
    
    # def testICM1(self):
    #     cipher = "RSTCS JLSLR SLFEL GWLFI ISIKR MGL"
    #     predictedKeyLength = 3
    #     language = "english"

    #     self.assertIn(predictedKeyLength, self.vb.indexOfCoincidenceMethod(cipher, language))

    def testICM2(self):
        cipher = "VVQGYTVVVKALURWFHQACMMVLEHUCATWFHHIPLXHVUWSCIGINCMUHNHQRMSUIMHWZODXTNAEKVVQGYTVVQPHXINWCABASYYMTKSZRCXWRPRFWYHXYGFIPSBWKQAMZYBXJQQABJEMTCHQSNAEKVVQGYTVVPCAQPBSLURQUCVMVPQUTMMLVHWDHNFIKJCPXMYEIOCDTXBJWKQGAN"
        predictedKeyLength = 8
        language = "english"

        self.assertIn(predictedKeyLength, self.vb.indexOfCoincidenceMethod(cipher, language))

    # def testKasiski0(self):
    #     cipher = "RSTCS JLSLR SLFEL GWLFI ISIKR MGL"
    #     predictedKeyLength = 3
    #     language = "english"

    #     print(self.vb.kasiskiMethod(cipher))

    #     self.assertIn(predictedKeyLength, self.vb.kasiskiMethod(cipher))

    # def testKasiski1(self):
    #     cipher = "VVQGYTVVVKALURWFHQACMMVLEHUCATWFHHIPLXHVUWSCIGINCMUHNHQRMSUIMHWZODXTNAEKVVQGYTVVQPHXINWCABASYYMTKSZRCXWRPRFWYHXYGFIPSBWKQAMZYBXJQQABJEMTCHQSNAEKVVQGYTVVPCAQPBSLURQUCVMVPQUTMMLVHWDHNFIKJCPXMYEIOCDTXBJWKQGAN"
    #     predictedKeyLength = [2, 3, 6, 4, 8, 9]

    #     self.assertIn(predictedKeyLength, self.vb.kasiskiMethod(cipher))

    # def testKasiski2(self):
    #     cipher = "LFWKIMJCLPSISWKHJOGLKMVGURAGKMKMXMAMJCVXWUYLGGIISWALXAEYCXMFKMKBQBDCLAEFLFWKIMJCGUZUGSKECZGBWYMOACFVMQKYFWXTWMLAIDOYQBWFGKSDIULQGVSYHJAVEFWBLAEFLFWKIMJCFHSNNGGNWPWDAVMQFAAXWFZCXBVELKWMLAVGKYEDEMJXHUXDAVYXL"
    #     key = "SYSTEM"
    #     KeyLength = 6

    #     self.assertIn(KeyLength, self.vb.kasiskiMethod(cipher))

    # def testIntersection1(self):
    #     cipher = "DAZFISFSPAVQLSNPXYSZWXALCDAFGQUISMTPHZGAMKTTFTCCFXKFCRGGLPFETZMMMZOZDEADWVZWMWKVGQSOHQSVHPWFKLSLEASEPWHMJEGKPURVSXJXVBWVPOSDETEQTXOBZIKWCXLWNUOVJMJCLLOEOFAZENVMJILOWZEKAZEJAQDILSWWESGUGKTZGQZVRMNWTQSEOTKTKPBSTAMQVERMJEGLJQRTLGFJYGSPTZPGTACMOECBXSESCIYGUFPKVILLTWDKSZODFWFWEAAPQTFSTQIRGMPMELRYELHQSVWBAWMOSDELHMUZGPGYEKZUKWTAMZJMLSEVJQTGLAWVOVVXHKWQILIEUYSZWXAHHUSZOGMUZQCIMVZUVWIFJJHPWVXFSETZEDF"
    #     key = "AMBROISETHOMAS"
    #     length = 14
    #     language = "english"

    #     self.assertIn(length, self.vb.intersection(cipher, language))

    # def testIntersection1(self):
    #     cipher = "Vsjnb m wmt xmofioub, dgruig ow bmi imtbtt, lug gq wbvutbbpi ecy uyowm vwyiic, zi vvvubbj dg qaghvkctz vlic m uyowef, mh dghqlzqpaww oeoda y raravw. Nuc rqzvvkctw vmrzm mr lgvx ij fcha xr bcmumh adfmhtmt dbdzruce zbzoamwn.Pqrq-mr kqmizzeprql b bgxmw qetpmf, bzcl x mnctwfi, pwoo nuv ptofcpi uovqvl siq ogqnisi zsvfgnhzcs ommbcwe, ieocnbhvdcg q wnzccmmmibopuf xqr lcvs ggflhbwrta gipugcfbkcta z swo roakco lwxicz, oiz dksmin a eiyjeqt uf xvpgz byfaqae wp cqzqnvdq nt dddc vggnvc. O fmnmq gq uctkct ijs vsjnba pah dzrdoum, giobxu xooddyrvfiwwn cqaa ozi cctw noewmf, qqhekmickozxb-ag shuznvs qg scpctw yau senecvukin e ecpctwu umqgibopif."
    #     key = "comunicativa"
    #     length = 12
    #     language = "portuguese"

    #     self.assertIn(length, self.vb.intersection(cipher, language))

    # def testIntersection2(self):
    #     cipher = "Vsjhq s gac ddcfiooq, jqfdox cw bmc xsdpcz, cig gq qqbehkhgw ecy onuga ecpwic, zc kbfikha rg qaawbuqcf mzic m onugso, sy rghqfowzofc fsoda s ggboec. Eic rqtkbuqcc marzm gg rqjg oa tcha rg hmadsy odfmbisd rkjqfuce tqfyovce.Dqrq-gg qaarfqsprqf q hqlvc hstpmz, qfmz g seqtwfc, ecyc wam dtofweo ecewmz siq ivwxwbo qgvfghwfmg xsdpcwe, ctumbknmrcg q qcfmqvsdwbopou daf uimg ggffwhgfcg xwpugwuhuqcg q gwo ripqmc ucowcz, oco jugvoe o eiydtwd io dmdgz bsugaon cg qqzqhkja bc jurc vgacbm. C oseaq gq orzuqc oag vsjhqg zoq jqfdoug, voypga ocoddsgbpwfce qqaa ioo mqcc ecewmz, fwrstszqkozrq-gq gqaqbvs qa hizqcc pou sehtifitoe s ecpwice ivwxwbopcu."
    #     key = "como"
    #     length = 4
    #     language = "portuguese"

    #     self.assertIn(length, self.vb.intersection(cipher, language))

    # def testIntersection3(self):
    #     cipher = "Vlxos w csn xwwfuvij, vqvotp ul nnr zgybvp, ick fm hwpsmqouu gbf erxuz fsfpgj, rg qtgcnbq dx kjmgrvvex rltr e csgpie, ms qmymtmbvvda xrftu v efseev. Spe vmlvvnkco tuklm wr wibv ab ievv dz xsuhru fjtagozr pmixvyfs srvohtjw.Hwjr-aj kqmizzezhrk s zvxgr zgybvp, gzgy m jaerbbj, caqb nqg grnwmeh sjgair dcj cviequa qwgkyzlrnv zgybvmk, wxtisqbawin e oeetgzvrvcefhs ksj aana javrnbprmw ybrmlifwmehs z wmi lhvhiq shkdax, gbf zojtnv e ebmkvaz az xfxgl imnsaey hy iflrwmxv nv zalg ucripa. H uzsys fx evcipd eqz tzblwy ait dgruids, fezuis tozsvglnymvwy pwrw wmt ixaa wbvmgc, dviitlnxmsvjb-aj aqmxvoe qq snriro qdw gztmylcxna j kqdbojs gxvemfrdbv."
    #     key = "chavesignificativamentegrande"
    #     length = 29
    #     language = "portuguese"

    #     self.assertIn(length, self.vb.intersection(cipher, language))

    # def testIntersection4(self):
    #     cipher = "Vlxos w csn xwwfuvij, vqvotp ul nnr zgybvp, ick fm hwpsmqouu gbf erxuz fsfpgj, rg qtgcnbq dx kjmgrvvex rltr e csgpie, ms qmymtmbvvda xrftu v efseev. Spe vmlvvnkco tuklm wr wibv ab ievv dz xsuhru fjtagozr pmixvyfs srvohtjw.Hwjr-aj kqmizzezhrk s zvxgr zgybvp, gzgy m jaerbbj, caqb nqg grnwmeh sjgair dcj cviequa qwgkyzlrnv zgybvmk, wxtisqbawin e oeetgzvrvcefhs ksj aana javrnbprmw ybrmlifwmehs z wmi lhvhiq shkdax, gbf zojtnv e ebmkvaz az xfxgl imnsaey hy iflrwmxv nv zalg ucripa. H uzsys fx evcipd eqz tzblwy ait dgruids, fezuis tozsvglnymvwy pwrw wmt ixaa wbvmgc, dviitlnxmsvjb-aj aqmxvoe qq snriro qdw gztmylcxna j kqdbojs gxvemfrdbv."
    #     key = "chavesignificativamentegrande"
    #     length = 29
    #     language = "english"

    #     self.assertIn(length, self.vb.intersection(cipher, language))


    # def testX2Method1(self):
    #     cipher = "NWAIWEBB RFQFOCJPUGDOJ VBGWSPTWRZ"
    #     key = "boy"
    #     length = 3
    #     language = "english"
    #     x2_1 = 17.0130

    #     self.assertIn(key, self.vb.x2Method(cipher, language))

    # def testX2Method2(self):
    #     cipher = "Vlxos w csn xwwfuvij, vqvotp ul nnr zgybvp, ick fm hwpsmqouu gbf erxuz fsfpgj, rg qtgcnbq dx kjmgrvvex rltr e csgpie, ms qmymtmbvvda xrftu v efseev. Spe vmlvvnkco tuklm wr wibv ab ievv dz xsuhru fjtagozr pmixvyfs srvohtjw.Hwjr-aj kqmizzezhrk s zvxgr zgybvp, gzgy m jaerbbj, caqb nqg grnwmeh sjgair dcj cviequa qwgkyzlrnv zgybvmk, wxtisqbawin e oeetgzvrvcefhs ksj aana javrnbprmw ybrmlifwmehs z wmi lhvhiq shkdax, gbf zojtnv e ebmkvaz az xfxgl imnsaey hy iflrwmxv nv zalg ucripa. H uzsys fx evcipd eqz tzblwy ait dgruids, fezuis tozsvglnymvwy pwrw wmt ixaa wbvmgc, dviitlnxmsvjb-aj aqmxvoe qq snriro qdw gztmylcxna j kqdbojs gxvemfrdbv."
    #     key = "chavesignificativamentegrande"
    #     length = 29
    #     language = "english"

    #     self.assertIn(key, self.vb.x2Method(cipher, language))

    # def testFindPossibleKeys(self):
    #     cipher = "NWAIWEBB RFQFOCJPUGDOJ VBGWSPTWRZ"
    #     key = "boy"
    #     length = 3
    #     language = "english"
    #     x2_1 = 17.0130

    #     self.assertIn(key, self.vb.findPossibleKeys(cipher, language, 3))