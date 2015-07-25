#[cfg(test)]
mod test {
    use set03::{MT19937};

    #[test]
    fn test_c21() {

        // Test vectors taken from http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
        // using the integer 0 as seed for MT19937.
        let v: [u32; 1000] = [
            0x8C7F0AAC, 0x97C4AA2F, 0xB716A675, 0xD821CCC0, 0x9A4EB343, 0xDBA252FB, 0x8B7D76C3, 0xD8E57D67, 0x6C74A409, 0x9FA1DED3,
            0xA5595115, 0x6266D6F2, 0x7005B724, 0x4C2B3A57, 0xE44B3C46, 0x0E84BDD8, 0xF6B29A58, 0x45CCCD8C, 0x6229393A, 0x7A4842C1,
            0xCAAE7DE6, 0xCFEA4A27, 0x8765A857, 0x7ADFC8AE, 0x916B5E58, 0x648D8B51, 0xECF3E6A5, 0xD6094219, 0x122F6B4D, 0x565F9848,
            0x164E1B09, 0xA5EE9794, 0x052D0873, 0x5E4513D0, 0xD52692F3, 0xF5081EC5, 0xC73547FE, 0x23EE074F, 0xDEB91DAF, 0xDEBE09C0,
            0xFA86BB52, 0x793E6063, 0xCC95A7D8, 0xCD087CB1, 0x762382F3, 0x853E031D, 0xC7D0C293, 0xADCB0C93, 0x1E473B8E, 0xB87B61A7,
            0xA3D1DD20, 0x94FF3FC1, 0x24B2CD09, 0x89914AB9, 0xF1D5D27F, 0xC234A220, 0x8597DA1F, 0x1B1CC2CA, 0x6A2748F4, 0x793DE097,
            0x43B9EAA3, 0x2FB379FE, 0xC6342DCB, 0xBCA6AB72, 0x74C644B7, 0x376FD81C, 0x9184E322, 0x229DA880, 0x04CF6880, 0x52FAE7A4,
            0x9E1D5C35, 0x26511785, 0x9CB24E26, 0x38EA0DE8, 0x9DEF62F4, 0x62F0F111, 0xF199794F, 0xE710B184, 0xAE8BC669, 0x732FEC2A,
            0x5C08B5BA, 0x9CF1BA1F, 0x6FE15378, 0xE7005101, 0xB297F541, 0x196A6FE7, 0x0F6AEFA9, 0xF8456839, 0xAAB13923, 0xA7342F66,
            0xABAEEC77, 0x2BC0BB0B, 0x35DBA1AE, 0x5BAFDC52, 0x2101505B, 0xC02CF780, 0x50BFE98E, 0x9B9ACA63, 0x5D1C2635, 0x53364B8C,
            0x91F86A79, 0x09D63FAA, 0x70483054, 0xA25FC8CB, 0xFD061144, 0xF57DB306, 0x1A1F9BC4, 0xA71D442F, 0x3578F27F, 0xA29337F4,
            0x294B9483, 0xFECBF3CC, 0xA7321B64, 0x94F424B4, 0x40D7B7E8, 0x6A140F4E, 0x7760248F, 0x7985C694, 0x3E92ACE3, 0x9F9E5BBA,
            0x28B23B17, 0x5687AACF, 0x1C418B8D, 0xACBC9175, 0xA8053755, 0x51342230, 0x235FF531, 0xC741A645, 0x325338A9, 0xF31716A3,
            0x5E64C5C0, 0xA99B5C5F, 0xD22C9CC5, 0x03796E5E, 0x18DBA100, 0x9F72D771, 0xD6838EB2, 0xAC74F524, 0x1899E7A2, 0xF8D16330,
            0xF9F93F5D, 0xE0D14983, 0x77F98662, 0x8276BE2A, 0xFA0D03CD, 0x0E435170, 0x9AD727E7, 0x737F2B95, 0xBD4060C9, 0x051DE97F,
            0x0A083600, 0x7113F78A, 0x48660972, 0xFAC6322B, 0x1EC533BA, 0x5C048D7F, 0x4BCFD817, 0x7B1BD6BB, 0x1E64F082, 0xB04C1979,
            0x51675862, 0xE166DE3E, 0x6A0D23A3, 0xEB117ADE, 0x106BF87B, 0x3781A7C3, 0xB145DA52, 0x90B037AE, 0x910CCAE3, 0xDD775C94,
            0x43F090D1, 0x824BCA32, 0x85F3959B, 0xEAAE5B0E, 0x180C7C29, 0xEBD0FC3A, 0x93713AC1, 0x1546DC24, 0xEDE65B0A, 0x47189056,
            0x518DBC2B, 0x02653368, 0xAADB680B, 0xD7A3BB02, 0x21BD8133, 0xA5AD3450, 0xB7613820, 0xD76514B6, 0x4A168480, 0x43C55B26,
            0x2EE5A113, 0x65D794AE, 0x9625B62A, 0x8D85B573, 0x0525C4B8, 0x2A3989BC, 0xD43569E8, 0x5EABBE4D, 0x0133B91E, 0x257D3518,
            0xAD85627D, 0x91D28302, 0x451F3E03, 0xB428205E, 0xBC35ACE2, 0x49D9976B, 0xF651FD0D, 0x6EEBF770, 0x3FAE4928, 0xC1903548,
            0x937F0C13, 0x6566B25F, 0x97900F48, 0xE562C59A, 0x927F19C2, 0xA39054F8, 0x391BE0B4, 0xE43CE943, 0xF3E75BEC, 0xAE181F3D,
            0x7276CF0E, 0x72FE9F60, 0xD8AE3D04, 0xFA839FC3, 0xB31112ED, 0x1DBF688B, 0x4C24D3FC, 0xC45BAA56, 0xD0550DCD, 0x696D0B79,
            0x6581666D, 0xACE9934B, 0xE18FFAB8, 0x3FF2A610, 0x94CE4C98, 0x502F139D, 0xE1B96895, 0xF725846E, 0xB149C019, 0x96A5A5D0,
            0xB9AA43BC, 0xA8E00779, 0x8056CB76, 0x88803475, 0xF4C1E5BD, 0x3B043653, 0xA4DC8AA1, 0x65162768, 0x6C81C3A0, 0x9E6A3CE4,
            0x9B3C95FB, 0x7990EAFB, 0x04E9D879, 0x785A9546, 0x4D3401D5, 0xB750A91F, 0xA901220D, 0x49B9C747, 0x4A4286B8, 0x622A9498,
            0x9E36424F, 0xBFC99829, 0x6DC3C912, 0xE0E23E28, 0x22AE6DB6, 0x1A5540CF, 0x4C5C3B0B, 0x17A5D0A6, 0x91E9386F, 0x5AA2CD5D,
            0x97436FF9, 0x8D43D481, 0x9306FADF, 0x089BA776, 0xA7382B2C, 0xF80DE0D8, 0xA6F03D7D, 0x522CE018, 0x6E717043, 0x38A4ABD2,
            0xE58413EF, 0x2429DF03, 0x5E1888EA, 0x18E606CC, 0x6F94D7E6, 0xFBEA3123, 0xE45516D6, 0x42A5B3FE, 0xCE62BABD, 0x897A4EC5,
            0xB4320AD7, 0x72AB4A2B, 0x19A87820, 0x197D5C0B, 0xEB633668, 0x5A3118D4, 0xB6D8848A, 0x7820B6B6, 0xFFB46FEB, 0xD754F5A5,
            0x26423E7D, 0xE796FE9C, 0xDE3D826F, 0x099D7DE8, 0x29992302, 0x8220F61B, 0x9D954FD3, 0x2AB684D9, 0x1FB2AA97, 0xC76FE335,
            0xD9171133, 0xDD6C44AE, 0xCEAC7494, 0x69514BB5, 0x91B0961D, 0x23D53E43, 0x683D2A23, 0x08814327, 0x11B4ED89, 0xFB8A0849,
            0xB28AB129, 0x5F8FFB97, 0x741B5F83, 0x6B8A0F2E, 0xB8D8A2DA, 0x0CF357B2, 0xDDCB3B6C, 0x5D912703, 0xF9BBC71F, 0x0441BB09,
            0xDB15ED8A, 0x3B11EE1B, 0x02FFB1AD, 0xC3D140C7, 0x5C2785A7, 0xF1B2143D, 0xBAE0A955, 0xBFFFF361, 0x2BEFEC2C, 0x56E32B22,
            0x8562A7A2, 0x7D531458, 0x0DE91821, 0x56C7BA85, 0x3332F8E8, 0x2DF312FF, 0x04BDD824, 0x2BC5C700, 0xCB2FC5CB, 0x76A4B922,
            0x395320C5, 0xDFE4037E, 0x5868F7B5, 0xF1B1D4FE, 0xED96BC50, 0x9BB675BE, 0xB4548088, 0x98BE68BD, 0x08269881, 0xC89CE8D1,
            0x2A296570, 0x8001B923, 0x9F193578, 0x0CE50D5B, 0x93C540A8, 0xB2F81774, 0x3CE68B24, 0xFE0DB0B0, 0xEF28A619, 0x446B5143,
            0x9D2CDF67, 0xADD8E1FC, 0x891F3B23, 0xDD418C72, 0x9704571E, 0xC037541D, 0xBAE946F1, 0xF6E8CD21, 0x4FDBA092, 0x8DE2D511,
            0x65F1D0DD, 0x365F3954, 0x35B851FD, 0x38F20A02, 0x2FAA5845, 0x37FFF565, 0xF1C2638C, 0x91CF922C, 0xBD533375, 0x73BD6AFD,
            0x7D8EB542, 0xF8616E6F, 0x3A37D85B, 0xAE382D55, 0x411D81A7, 0x15D5EE27, 0x0EDAFFCB, 0x0E716E96, 0x6F35ED9E, 0x7CE2EE91,
            0x4FD1DAC6, 0xE18983C7, 0xB2439112, 0xF9F5A35C, 0x60B4582B, 0x9E1ED453, 0x2DFA81B1, 0x8AE13329, 0x0651585D, 0xDAC7F4AE,
            0x11374595, 0xBE6BF0C9, 0xADECAF59, 0x7A8549F2, 0x742579E0, 0xAD5537DB, 0x895D4149, 0x9B674E1C, 0xE58C3FEB, 0xB6F660D1,
            0xFD86DA69, 0x7830F7BA, 0x37868F80, 0x74BD5FD6, 0xA9BF7E3F, 0xE80B0410, 0x4369186A, 0x2320E0A4, 0x0549625E, 0x3AAE1E18,
            0xC2251A74, 0xE1AF94BF, 0x51ECA4C3, 0xE7886533, 0x622AB088, 0xA55223B8, 0x969BF35B, 0x531E6C5D, 0xD4BF977B, 0x850BCAEE,
            0xA104F457, 0x0003A0A0, 0xDF660893, 0x4FD61248, 0x4606D9C7, 0x6CEA6457, 0xCC4CCC0D, 0xE2A57D3A, 0x2F85D651, 0xAE0C9478,
            0xF3EA2774, 0x74C4EBB7, 0xAFFF3B40, 0x7BC0AACB, 0x372B82DC, 0xC9EAD3A4, 0xF286E119, 0x3ABCB320, 0xBB195DAA, 0xE15B2F0E,
            0x410251D6, 0x504E251C, 0x369B9D14, 0xF51B7FD2, 0x84A8CD44, 0x78C4B616, 0x0691D4E3, 0xB62A5B7A, 0x351CC253, 0x27588287,
            0x6CB82FC8, 0xBAFE423D, 0x5FC99A8D, 0xA5719605, 0x76ACE100, 0x37026C88, 0x4712ACCF, 0x2FBBB9CF, 0x96377FB5, 0xCEBD948B,
            0xDD25A404, 0xBF4099A7, 0x1E16915C, 0xACC2CBAD, 0x8472F51A, 0x46E2824A, 0x21CF3734, 0x2CC6D3EE, 0xB7841DB1, 0xB4586CDB,
            0x65642B33, 0x769102E3, 0x90BF7369, 0xD7265312, 0x2EEB6D75, 0x34721522, 0x2514BE33, 0x2A3ABE9E, 0x7CF141B5, 0x1FF50F3A,
            0x5B096FAB, 0xB8DA4737, 0xF0C025FC, 0x07CBC3FC, 0xC3EC5B12, 0xBF3B03AD, 0xBFA86B57, 0x17B461C1, 0xE75A2D46, 0x37AAD5EA,
            0x155B2C35, 0xBFCF2330, 0x8D5C7C5E, 0xBB50483B, 0x95A03950, 0x0BAD669A, 0xF641767C, 0x358B50A3, 0x4ACA2E3A, 0x497343B1,
            0x3DA6F46A, 0xAD6120C9, 0x19ACDD2C, 0x1023470D, 0x0434BB79, 0x8E3F0746, 0xEDF5A226, 0x025D8EA7, 0xAB7FA688, 0xD541FC0D,
            0xC8FFC7F8, 0xFBFD0387, 0x481F76D0, 0xB4183BF8, 0x961EFA16, 0x2E7F61F8, 0x105F5F4F, 0x832C37D9, 0x7C521708, 0x94982EE3,
            0xFA3D1F06, 0xC99C5CD1, 0xE062A5C7, 0x9B41F9D4, 0x569195D9, 0x37E93FC2, 0xF629763C, 0x7485F190, 0x3B50CC38, 0xE0FD9B72,
            0xF3068EED, 0x7E054A97, 0xF0FE2118, 0xB72F0404, 0xCC988A64, 0x7C74F3EC, 0xA1650931, 0xB5636957, 0xDFD1561E, 0x7F861E36,
            0x4B036099, 0xD8346F14, 0xD9545D61, 0x31C06965, 0x9E2D2AB9, 0xC5F8B197, 0x03637D9B, 0xF969041D, 0x58E44BA1, 0xDCC05573,
            0x25EC8F35, 0xC7CA0A77, 0xFB592BB3, 0xFC2B1356, 0x7A7679F6, 0xC0E9F007, 0x7F550A69, 0x01094BF1, 0xA3B47889, 0x44FC9AB6,
            0x5E5B8F80, 0x69160353, 0x230BE578, 0x6DA013A4, 0xD2764ED1, 0x4C3F5C94, 0x3099DF75, 0x66B09BF0, 0x82E5CD03, 0x1EE3607E,
            0x396CD72A, 0xFB0F2241, 0x190C5614, 0x67F78324, 0xDCB89544, 0x91B7CBD0, 0xF9114070, 0x57F687AF, 0xF5F9428A, 0xC9F390ED,
            0xE8140568, 0x694FB3DE, 0xC627F75B, 0x5BF9362B, 0x5549003F, 0x66458F9F, 0x14C30F94, 0x4D44C9C6, 0x6840F509, 0xC674CDBC,
            0x3B73B25B, 0xED1C4A6F, 0x21EAB5A3, 0x53478953, 0x0DAD674C, 0xF3EF5512, 0xB9C08D71, 0x03921F4A, 0x02ECE8E2, 0x889134E1,
            0xC544C7AB, 0x4DF91683, 0x259E4B8C, 0xE2031CE4, 0x145B8F3A, 0x4028CF81, 0x16F03971, 0xAD6ADC80, 0xAC0B5327, 0xCF77F418,
            0x3ED062BA, 0x6EA14124, 0x6BA87963, 0xC08BE345, 0x8EAFB886, 0xD460D003, 0xDC4D14E2, 0x61085B79, 0xBA1F92A8, 0x18B779BC,
            0x453435A1, 0x41925D1C, 0x21A8DB44, 0x9789101A, 0x0E2D02E0, 0x79FA68F8, 0x4D35916D, 0x7CE947B3, 0x431A2CC9, 0x756135B5,
            0x74C5A0C5, 0x864BB3A1, 0xAEEB8687, 0x7127EA7D, 0xB214825E, 0xDA464848, 0x4894B0F6, 0x6EF5DB54, 0x6142E487, 0xD3ADC6C3,
            0x2E5FE8D5, 0x82643DDB, 0xC9DE1E6C, 0x161CCD43, 0x0E8D9866, 0xA8F85F54, 0xB26E6947, 0x34E36253, 0xC75894DF, 0xD8E70900,
            0xC7042E85, 0xAE6D8D5B, 0x4269846B, 0x2DA97B9E, 0x5FB237C9, 0x11E247D3, 0x966CEE07, 0x027AEC95, 0x45D7A7E5, 0xE45D5DDC,
            0x5EF03588, 0x222AC6AB, 0x3272262E, 0xC7792000, 0x75B91D68, 0xECD782B3, 0x0B6BB626, 0xB715F459, 0xCCBF6C4A, 0x7DA649F3,
            0x13B36AE2, 0x78310A7B, 0x84D26157, 0xE1F93C60, 0x4E8B1B53, 0x7D08711A, 0x93D9DACE, 0x6A211820, 0xF59D6C73, 0x2C9299C6,
            0xA5441761, 0x79AC91AC, 0x090D833B, 0xC89D2739, 0x6E2EDAB2, 0x8E7228AD, 0x829076E9, 0x28ED0C84, 0x8942EDB9, 0x24D2005D,
            0xAE6FBD5B, 0xA6433591, 0x471089A3, 0x8A0A8EC2, 0x20FD0194, 0x536013AD, 0x648664B9, 0x25A2B3CF, 0xF4D70177, 0x28ED3EA4,
            0x2FE7CF69, 0x21212ABE, 0xE76B7E04, 0x943441F1, 0x8B36DDF2, 0x179E5CCD, 0x74F8259E, 0xE919756D, 0xE1CD7757, 0x153DA2E2,
            0x756711A3, 0xCCE59A49, 0xB9630CDA, 0xE08BA7B7, 0x6626861A, 0x17ECF576, 0xE76F7416, 0x6D2261CC, 0xB0A57ACF, 0x7924FD62,
            0xB31A6E5A, 0x9487CC33, 0x53E57BE6, 0xB75BC72E, 0xC1BC3ED0, 0x06EDFE3D, 0xA2D4E5BC, 0xBB3CDB2F, 0x3D71F7FA, 0xC457B868,
            0x29191280, 0x02800D8A, 0xCBE04FCB, 0x4EEBD78D, 0xF58BF147, 0x3B9D125E, 0x75489606, 0x80E09EAD, 0x974ABCF5, 0xF427159E,
            0xDB93B60F, 0x8ECCB8A9, 0x750C98A6, 0x18F3B535, 0xF3AE0BAB, 0x9F265252, 0x93646D87, 0xDCEF0CDC, 0xD21DCB41, 0x285A96A9,
            0xE8A9FB42, 0xFE0FDC72, 0xD0C62B5C, 0x15C2A14E, 0x28CF62E5, 0x182E64DB, 0xA0FF7CF6, 0xA2342064, 0x65FFC99F, 0xF30528DD,
            0x100DF4B2, 0xEFCE9DFC, 0x6C8D60AE, 0x7287625D, 0x42391E72, 0xBA4A4EA1, 0xD95A930C, 0xBE034EE0, 0x0886A6E9, 0x4E96A350,
            0xF57FE442, 0x1EA955C8, 0x5AF973F3, 0x71A2087D, 0x5B51248A, 0x644B5270, 0x042E1ADA, 0x8827449B, 0x2F6B62B8, 0xD8695C78,
            0x66B8F141, 0x894949C0, 0xEDE60AC5, 0xAE262F58, 0x19805D22, 0x9BF30FCF, 0xF1FF4803, 0x1935DABC, 0xDE96CCEE, 0x178F1EA5,
            0x7443FCAB, 0x0E53C6D3, 0x53A2AB58, 0x1626FE46, 0x3B951E94, 0x3CB76386, 0x9D4D8F1C, 0xD6EA5273, 0x08779386, 0x85BA1342,
            0x03FEC25C, 0x8358DFDC, 0x6DC58E66, 0xA65B6365, 0x116D4D7B, 0x8B6A4EC5, 0x407F346D, 0x084FA549, 0x389E0064, 0x9484D2B6,
            0x40D1234D, 0xC5661795, 0x218CD5FB, 0x6050629F, 0x0314CE51, 0x7DB3CC23, 0x1D9060ED, 0xFB4CBCF3, 0x9E54B8FA, 0x3EA17988,
            0xF968DAFE, 0x5FD3A519, 0xFD874015, 0x0BB059AD, 0x68B7C4E5, 0x4F6097D6, 0x29B76190, 0xD4DE7499, 0xA385E3EE, 0xCE990C77,
            0x7D84A6A5, 0xA3D89F7F, 0xFD49F581, 0x5E3BF585, 0x10B7C6C6, 0x5010998C, 0xC8820D5A, 0xCD45224A, 0x49D47BFB, 0x1208D3B6,
            0x3DCD9C4E, 0xAEFEA33E, 0xA999E648, 0x617778C7, 0x3EFDFF2D, 0xA2494C85, 0xAA75BE2F, 0xED47F2BB, 0x846E54AA, 0xDA9BD1C3,
            0x6C91188A, 0x7F67D2F2, 0x8E000539, 0x6D868DDB, 0x497C3559, 0xD2934183, 0xB4E2147D, 0xBCFC6ACE, 0x6A340F52, 0x727804C5,
            0x5C4CB6BA, 0xF80A0784, 0xD422DC11, 0x5CF822C5, 0xECCAA1BF, 0x65C4C15E, 0x0BC72298, 0xBD1A4E83, 0x3B8D7145, 0x72F721A8,
            0x593890A4, 0xEFF1DE3A, 0xD0A1A4B1, 0x41DA0DB7, 0xFC492A98, 0x61BB02A1, 0xF80E8792, 0xB277DF61, 0xE7AAB1CE, 0xE5A662F1,
            0x4BEB1C87, 0x1EFDC7B5, 0xFDF472EB, 0x3DD5F02E, 0x3FD9FDF0, 0x3A6F7BF4, 0x1B1CAA7F, 0x7D507BA1, 0xF371A151, 0xE43AD49D,
            0x3BC16E0C, 0x5BACEE76, 0xB094A72E, 0x629EEB76, 0x0EF07120, 0xEAAE9F22, 0xBB0FC073, 0x1D231657, 0xE1B86A7C, 0xA1917199,
            0x45BE6CAE, 0x220029F2, 0x6109DF6B, 0x5FCE7E34, 0x5FD1DFE9, 0x530C326E, 0xBFB09640, 0xAE1C0D4C, 0x3CE0EF76, 0xCBA82A49,
            0x2BFE9092, 0x8101CB04, 0x7304C707, 0x4BD68A83, 0x4DF1A430, 0xE2CE6C4C, 0xD6D51925, 0x5A143074, 0x3CDCA5ED, 0xBD072630,
            0x809C986D, 0x8E2C27D2, 0xF14D28B3, 0x3396AA31, 0xA24DAC47, 0x8C6BBF5A, 0xDE06ADB1, 0x85074FEE, 0xF0B1951D, 0x5949D203,
            0xC032204A, 0x064D7E54, 0xB31759EA, 0x2619AD41, 0xF7CC9777, 0x21C10E14, 0xFE910CD0, 0xB53A142A, 0x73AA95F2, 0xB585C01C,
            0x1224859A, 0x9C9B8B57, 0x4AF48CB4, 0xAC021930, 0x2700B7C2, 0x72906666, 0x6AE06309, 0xB2321D02, 0x219C2D74, 0x60D9FB6C,
            0x9AA776E9, 0x199BB359, 0x61FFB57C, 0xF5D36375, 0xE5380264, 0x128B105A, 0xF7C16444, 0x04F0E269, 0x8C00A60A, 0xFAC5500C,
            0x465AD668, 0x2602A8E1, 0x979C69A5, 0x423A50A7, 0xE59223A0, 0x372CE57A, 0x681FAD21, 0x9475239A, 0x8D550063, 0xF9CADCD9,
            0x458B0932, 0x45E3E958, 0x7497FCD2, 0xF856D714, 0x66D6B2DE, 0x0686FE9C, 0x3F980648, 0xE356D512, 0x81807599, 0xB5676398 ];

            let mut mt = MT19937::new();
            mt.seed(0);
            for i in 0..1000 {
                assert_eq!(v[i],mt.generate_random_u32());
            }
    }
}