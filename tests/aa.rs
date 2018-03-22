extern crate pkauth;
extern crate ring;
extern crate serde_json;

use pkauth::{PKAJ, ToPublicKey, ToIdentifier};
use pkauth::asym::auth as aa;
use pkauth::internal;
use ring::rand::{SystemRandom, SecureRandom};

#[test]
fn aa_random_test() {
    fn run() {
        // Generate a random key.
        let rng = SystemRandom::new();
        let key = aa::gen( &rng, &aa::Algorithm::AAEd25519).unwrap();
        let pk = ToPublicKey::to_public_key( &key);

        // Generate something to sign.
        let mut content = [0u8; 256].to_vec();
        rng.fill( &mut content).unwrap();

        // Sign it.
        let signed = aa::sign_content( &key, content.clone()).unwrap();
        
        // Convert to JSON.
        let key = serde_json::to_string( &PKAJ{pkaj: &key}).unwrap();
        let pk = serde_json::to_string( &PKAJ{pkaj: &pk}).unwrap();
        let signed = serde_json::to_string( &signed).unwrap();

        aa_manual_test( &key, &pk, content, &signed)
    }

    for _ in 1 .. 100 {
        run()
    }
}

fn aa_manual_test(priv_key : &str, pub_key : &str, content : Vec<u8>, s_content :
&str){
    let priv_key = priv_key.to_owned().into_bytes();
    let pub_key = pub_key.to_owned().into_bytes();
    let s_content = s_content.to_owned().into_bytes();

    let priv_key : PKAJ<aa::PrivateKey> = serde_json::from_slice( &priv_key).unwrap(); // .pkaj;
    let priv_key = priv_key.pkaj;

    let pub_key : PKAJ<aa::PublicKey> = serde_json::from_slice( &pub_key).unwrap(); // .pkaj;
    let pub_key = pub_key.pkaj;

    let s_content : aa::PKASigned = serde_json::from_slice( &s_content).unwrap();

    // Verify public key and private key are pairs.
    assert_eq!( pub_key, ToPublicKey::to_public_key( &priv_key));

    // Verify signature.
    let verified = aa::verify_content( &pub_key, s_content).unwrap();
    assert_eq!( verified, content);
}

fn hex_to_u8( hex : &str)  -> Vec<u8> {
    let c = hex.len()/2;
    let mut v = vec![0;c];

    for i in 0 .. c {
        v[i] = u8::from_str_radix( &hex[2*i .. 2*i + 2], 16).unwrap();
    }

    v
}

fn ed25519_rfc_test( private : &str, public : &str, message : &str, signature : &str) {
    let mut public_key = "{\"public_key\":\"".to_string();
    public_key.push_str( &internal::serialize_base64url( &hex_to_u8( public)));
    public_key.push_str( "\",\"algorithm\":\"aa-ed25519\"}");

    let mut private_vec = hex_to_u8( private);
    private_vec.append( &mut hex_to_u8( public));
    let mut private_key = "{\"algorithm\":\"aa-ed25519\",\"private_key\":\"".to_string();
    private_key.push_str( &internal::serialize_base64url( &private_vec));
    private_key.push_str( "\"}");

    let raw_message = hex_to_u8( message);
    let message = &internal::serialize_base64url( &hex_to_u8( message));

    // Parse public key.
    let pk : PKAJ<aa::PrivateKey> = serde_json::from_str( &private_key).unwrap();
    let identifier = ToIdentifier::to_identifier( &pk.pkaj);

    let mut signature_b = "{\"signature\":\"".to_owned();
    signature_b.push_str( &internal::serialize_base64url( &hex_to_u8( signature)));
    signature_b.push_str( "\",\"identifier\":\"");
    signature_b.push_str( &identifier);
    signature_b.push_str( "\",\"content\":\"");
    signature_b.push_str( message);
    signature_b.push_str( "\",\"algorithm\":\"aa-ed25519\"}");

    aa_manual_test( &private_key, &public_key, raw_message, &signature_b);
}

#[test]
fn aa_manual_tests() {
    // From RFC8032.
    ed25519_rfc_test( 
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
    ed25519_rfc_test( 
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 
        "", 
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    ed25519_rfc_test( 
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        );
    ed25519_rfc_test( 
		"f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
		"278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        );
    ed25519_rfc_test(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        );

	aa_manual_test(
		"{\"algorithm\":\"aa-ed25519\",\"private_key\":\"Jg0dbvyT9LImDR1u_JP0siYNHW78k_SyJg0dbvyT9LJ8FYC5TgtSnlxHYfo-v_aXpBabatIlDzJw87eTjUL_yw==\"}",
		"{\"public_key\":\"fBWAuU4LUp5cR2H6Pr_2l6QWm2rSJQ8ycPO3k41C_8s=\",\"algorithm\":\"aa-ed25519\"}", 
		"".to_owned().into_bytes(),
		"{\"signature\":\"zxW1qxudeD5nprRf5xMhC_FNAlIEQmtB7KPXnZzonIZu6miywsCLuCxSU6vxIryulqDRbZinL5yvAGcPEk7bDQ==\",\"identifier\":\"8ZsJKn2QSMjQyssExb7KZzK9VK5qryExz\",\"content\":\"\",\"algorithm\":\"aa-ed25519\"}"
	); 
	aa_manual_test(
		"{\"algorithm\":\"aa-ed25519\",\"private_key\":\"Jg0dbvyT9LImDR1u_JP0siYNHW78k_SyJg0dbvyT9LJ8FYC5TgtSnlxHYfo-v_aXpBabatIlDzJw87eTjUL_yw==\"}",
		"{\"public_key\":\"fBWAuU4LUp5cR2H6Pr_2l6QWm2rSJQ8ycPO3k41C_8s=\",\"algorithm\":\"aa-ed25519\"}", 
		"shelled pistachios".to_owned().into_bytes(),
 
		"{\"signature\":\"ZG4XAMOu16WZrASwn7ADwzYBzH4nXnjF7WUBZEzVh8V5XPKZvlx0SlabG4iuivrghHaaw2Bc2Z8rqKQy8c93AQ==\",\"identifier\":\"8ZsJKn2QSMjQyssExb7KZzK9VK5qryExz\",\"content\":\"c2hlbGxlZCBwaXN0YWNoaW9z\",\"algorithm\":\"aa-ed25519\"}"
	); 
	aa_manual_test(
		"{\"algorithm\":\"aa-ed25519\",\"private_key\":\"Gi-kD64CwTYaL6QPrgLBNhovpA-uAsE2Gi-kD64CwTZvwNWsATeieamFLzovnITWQ4a4wt2iBoi4hFbkRmZXmg==\"}", 
		"{\"public_key\":\"b8DVrAE3onmphS86L5yE1kOGuMLdogaIuIRW5EZmV5o=\",\"algorithm\":\"aa-ed25519\"}",
		"Haribo Gold-bears".to_owned().into_bytes(),

		"{\"signature\":\"ElnnndP57CZZApMq1c8hiZ5Vze45vjbOD1CPFAoibhIv1yN0l2MErM8p6nyWXnZDiHkP6WMirJGIX1OLX0MRCQ==\",\"identifier\":\"MijeyEWKvcciSvDCd3k1rxEbmQXtcgMRs\",\"content\":\"SGFyaWJvIEdvbGQtYmVhcnM=\",\"algorithm\":\"aa-ed25519\"}"
	); 
	aa_manual_test(
		"{\"algorithm\":\"aa-ed25519\",\"private_key\":\"Gi-kD64CwTYaL6QPrgLBNhovpA-uAsE2Gi-kD64CwTZvwNWsATeieamFLzovnITWQ4a4wt2iBoi4hFbkRmZXmg==\"}", 
		"{\"public_key\":\"b8DVrAE3onmphS86L5yE1kOGuMLdogaIuIRW5EZmV5o=\",\"algorithm\":\"aa-ed25519\"}",
		vec![0x0A, 0x20, 0x0B, 0x20, 0xDE, 0x20, 0xAD, 0x20, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x20, 0xFF, 0x20, 0xFF, 0x20, 0x00],
		"{\"signature\":\"EYO-liRbTrup7LuFWCaF77pD36si-oSH92K4bIlNtFsBZW6rhJOEWh2Zjg9pQpIvM_grFTXL0dXel9iImwNeCQ==\",\"identifier\":\"MijeyEWKvcciSvDCd3k1rxEbmQXtcgMRs\",\"content\":\"CiALIN4grSAqKioqKioqKioqKioqKiD_IP8gAA==\",\"algorithm\":\"aa-ed25519\"}"
	); 

	aa_manual_test(
		"{\"algorithm\":\"aa-ed25519\",\"private_key\":\"Gi-kD64CwTYaL6QPrgLBNhovpA-uAsE2Gi-kD64CwTZvwNWsATeieamFLzovnITWQ4a4wt2iBoi4hFbkRmZXmg==\"}", 
		"{\"public_key\":\"b8DVrAE3onmphS86L5yE1kOGuMLdogaIuIRW5EZmV5o=\",\"algorithm\":\"aa-ed25519\"}",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce quis diam vehicula, scelerisque felis ac, vehicula justo. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Fusce ullamcorper gravida metus non vestibulum. Aliquam accumsan elit nec mauris tincidunt suscipit. Donec nec bibendum nunc, et venenatis arcu. In malesuada sagittis rutrum. Aenean sit amet mi quis ante fermentum venenatis. Cras rhoncus interdum porttitor. Nam at imperdiet justo. Vivamus venenatis lacinia elit in auctor. Duis tincidunt scelerisque risus in iaculis. Nunc facilisis eros eu pellentesque ultrices. Nullam eget cursus tortor, vulputate aliquet sapien. Aenean gravida ullamcorper justo, in faucibus nisi ultrices ac. Morbi feugiat ante eget rutrum imperdiet. Duis at posuere risus, sed maximus turpis. Sed eget lobortis sapien. Cras porttitor, nulla et tempor sollicitudin, nibh est mattis ex, imperdiet ultrices lacus sapien et tellus. Donec quis dui auctor, imperdiet libero nec, iaculis mauris. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Donec ornare ipsum sed diam ultrices, eget fermentum augue accumsan. Curabitur eros nisi, venenatis lobortis neque vel, luctus efficitur nibh. Mauris eu maximus purus. Phasellus consequat odio commodo justo faucibus, eu rutrum diam facilisis. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Fusce egestas feugiat nunc nec faucibus. Aenean nisl diam, ullamcorper sit amet ante ac, tincidunt porttitor lacus. Vivamus fringilla, ex eget congue dignissim, enim mauris tristique felis, sit amet laoreet libero nulla eget purus. Nulla facilisi. Suspendisse dolor purus, malesuada sit amet magna at, vulputate laoreet arcu. Vestibulum iaculis nibh a velit imperdiet, id rutrum turpis scelerisque. Phasellus laoreet sapien non rutrum rhoncus. Etiam fringilla at erat nec mollis. Suspendisse viverra posuere dui. Etiam eleifend sollicitudin urna, in tempus felis. Integer malesuada sodales lorem vel condimentum. Phasellus malesuada tincidunt sem in blandit. Fusce non mollis sapien. Ut id dictum lectus, eget accumsan risus. Mauris sed viverra ligula, a egestas neque. Praesent consequat massa vel vulputate efficitur. Curabitur semper, eros eget pellentesque aliquet, sem massa scelerisque nisl, id consequat elit massa sit amet lectus. Donec facilisis convallis commodo. Phasellus tristique tempor lorem, dictum ullamcorper felis elementum eu. Nunc a ligula sed orci bibendum maximus. Nullam facilisis semper tortor eu fringilla. Aliquam nec pulvinar tellus. Vivamus pulvinar leo lectus, vel dignissim leo sagittis at. Quisque dapibus mauris sed nunc facilisis, a mattis purus venenatis. Vivamus ut interdum leo, a interdum elit. Nam maximus porttitor libero nec posuere. Integer diam odio, iaculis ut enim eget, porttitor vulputate diam. Morbi eu neque risus. Curabitur fermentum at lacus nec porttitor. Integer et massa vitae mauris pretium tristique eu at nisi. Nam at dapibus nisi. Fusce dignissim ipsum sit amet augue molestie dapibus. Ut sapien mauris, laoreet sed magna eget, hendrerit ullamcorper lectus. Cras molestie nunc quis vestibulum sagittis. Quisque quis vestibulum risus. Aenean ut magna in eros malesuada scelerisque. Sed feugiat fermentum nisi sed faucibus. Nullam at lobortis urna. Phasellus dictum est diam, quis volutpat tortor sodales in. Sed in est commodo, condimentum risus quis, sagittis lacus. Quisque tincidunt commodo urna at molestie. Nulla a diam tortor. Nunc viverra ipsum id mauris sollicitudin iaculis. Nullam vulputate hendrerit est facilisis efficitur. Praesent lacinia consectetur orci, eget fermentum magna mattis at. Curabitur vitae eleifend tellus, sed luctus urna. Nam egestas velit tellus. Cras ac augue diam. Nullam vel tellus elit. Etiam nisi diam, auctor ut felis eu, fermentum volutpat ligula. Phasellus faucibus condimentum pharetra. Nam eu nunc sed tortor pellentesque elementum. Nam maximus justo eu ipsum dictum, eget sodales lorem vehicula. Aenean facilisis neque vel ornare interdum. Sed accumsan nisl molestie velit interdum, nec sagittis eros congue. Proin varius augue vitae enim dapibus, eget tristique justo dictum. Maecenas bibendum quam eu varius semper. Vivamus efficitur justo a varius maximus. Donec non ipsum luctus, ornare nibh nec, fermentum ligula. Ut id placerat leo. Curabitur feugiat mattis congue. Suspendisse tincidunt felis tempus, mollis sapien non, rhoncus augue. Vestibulum non pulvinar orci. Sed tempus non lorem et feugiat. Curabitur ultricies sed nisi ac efficitur. Duis pellentesque, metus eget malesuada sodales, neque orci vestibulum augue, non pretium augue est ac enim. Proin egestas, quam quis tincidunt sodales, ipsum mauris congue turpis, ac rhoncus enim justo ac urna. Suspendisse potenti. Praesent ac eros vitae lacus rutrum efficitur. Aliquam at tincidunt nunc. Quisque posuere mauris nec libero venenatis vehicula. Pellentesque sollicitudin interdum commodo. Mauris hendrerit aliquam neque id faucibus. Etiam maximus tellus aliquet nisl tempor mattis. Suspendisse potenti. Aenean dignissim iaculis fermentum. Proin tellus enim, dictum eget feugiat et, sollicitudin eu lorem. Donec dignissim tempor quam quis luctus. Sed odio leo, faucibus in purus quis, tempus lobortis dolor. Integer sit amet vulputate dui. Praesent urna ipsum, hendrerit id eros nec, fringilla mattis orci. Morbi ut iaculis nisl, nec iaculis nunc. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Nam ut ligula non tellus eleifend iaculis eu vel quam. Sed turpis ipsum, commodo nec justo ac, sollicitudin scelerisque augue. Sed eget eros maximus, commodo elit vitae, blandit nunc. Curabitur auctor varius ipsum sit amet egestas. Suspendisse purus dolor, venenatis in arcu congue, ullamcorper dapibus massa. Maecenas a quam accumsan, condimentum justo quis, porttitor nibh. Curabitur ex erat, pellentesque nec massa in, rutrum ornare lectus".to_owned().into_bytes(), 
		"{\"signature\":\"wB4waBKpwXVf_LEfimQ5NjgXjx4rIBxoWyQutG2-sBoclHAKDU2QQDJnHVqxB67BN35bnpLVHo7NB011oWWFCA==\",\"identifier\":\"MijeyEWKvcciSvDCd3k1rxEbmQXtcgMRs\",\"content\":\"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gRnVzY2UgcXVpcyBkaWFtIHZlaGljdWxhLCBzY2VsZXJpc3F1ZSBmZWxpcyBhYywgdmVoaWN1bGEganVzdG8uIENsYXNzIGFwdGVudCB0YWNpdGkgc29jaW9zcXUgYWQgbGl0b3JhIHRvcnF1ZW50IHBlciBjb251YmlhIG5vc3RyYSwgcGVyIGluY2VwdG9zIGhpbWVuYWVvcy4gRnVzY2UgdWxsYW1jb3JwZXIgZ3JhdmlkYSBtZXR1cyBub24gdmVzdGlidWx1bS4gQWxpcXVhbSBhY2N1bXNhbiBlbGl0IG5lYyBtYXVyaXMgdGluY2lkdW50IHN1c2NpcGl0LiBEb25lYyBuZWMgYmliZW5kdW0gbnVuYywgZXQgdmVuZW5hdGlzIGFyY3UuIEluIG1hbGVzdWFkYSBzYWdpdHRpcyBydXRydW0uIEFlbmVhbiBzaXQgYW1ldCBtaSBxdWlzIGFudGUgZmVybWVudHVtIHZlbmVuYXRpcy4gQ3JhcyByaG9uY3VzIGludGVyZHVtIHBvcnR0aXRvci4gTmFtIGF0IGltcGVyZGlldCBqdXN0by4gVml2YW11cyB2ZW5lbmF0aXMgbGFjaW5pYSBlbGl0IGluIGF1Y3Rvci4gRHVpcyB0aW5jaWR1bnQgc2NlbGVyaXNxdWUgcmlzdXMgaW4gaWFjdWxpcy4gTnVuYyBmYWNpbGlzaXMgZXJvcyBldSBwZWxsZW50ZXNxdWUgdWx0cmljZXMuIE51bGxhbSBlZ2V0IGN1cnN1cyB0b3J0b3IsIHZ1bHB1dGF0ZSBhbGlxdWV0IHNhcGllbi4gQWVuZWFuIGdyYXZpZGEgdWxsYW1jb3JwZXIganVzdG8sIGluIGZhdWNpYnVzIG5pc2kgdWx0cmljZXMgYWMuIE1vcmJpIGZldWdpYXQgYW50ZSBlZ2V0IHJ1dHJ1bSBpbXBlcmRpZXQuIER1aXMgYXQgcG9zdWVyZSByaXN1cywgc2VkIG1heGltdXMgdHVycGlzLiBTZWQgZWdldCBsb2JvcnRpcyBzYXBpZW4uIENyYXMgcG9ydHRpdG9yLCBudWxsYSBldCB0ZW1wb3Igc29sbGljaXR1ZGluLCBuaWJoIGVzdCBtYXR0aXMgZXgsIGltcGVyZGlldCB1bHRyaWNlcyBsYWN1cyBzYXBpZW4gZXQgdGVsbHVzLiBEb25lYyBxdWlzIGR1aSBhdWN0b3IsIGltcGVyZGlldCBsaWJlcm8gbmVjLCBpYWN1bGlzIG1hdXJpcy4gVmVzdGlidWx1bSBhbnRlIGlwc3VtIHByaW1pcyBpbiBmYXVjaWJ1cyBvcmNpIGx1Y3R1cyBldCB1bHRyaWNlcyBwb3N1ZXJlIGN1YmlsaWEgQ3VyYWU7IERvbmVjIG9ybmFyZSBpcHN1bSBzZWQgZGlhbSB1bHRyaWNlcywgZWdldCBmZXJtZW50dW0gYXVndWUgYWNjdW1zYW4uIEN1cmFiaXR1ciBlcm9zIG5pc2ksIHZlbmVuYXRpcyBsb2JvcnRpcyBuZXF1ZSB2ZWwsIGx1Y3R1cyBlZmZpY2l0dXIgbmliaC4gTWF1cmlzIGV1IG1heGltdXMgcHVydXMuIFBoYXNlbGx1cyBjb25zZXF1YXQgb2RpbyBjb21tb2RvIGp1c3RvIGZhdWNpYnVzLCBldSBydXRydW0gZGlhbSBmYWNpbGlzaXMuIFZlc3RpYnVsdW0gYW50ZSBpcHN1bSBwcmltaXMgaW4gZmF1Y2lidXMgb3JjaSBsdWN0dXMgZXQgdWx0cmljZXMgcG9zdWVyZSBjdWJpbGlhIEN1cmFlOyBGdXNjZSBlZ2VzdGFzIGZldWdpYXQgbnVuYyBuZWMgZmF1Y2lidXMuIEFlbmVhbiBuaXNsIGRpYW0sIHVsbGFtY29ycGVyIHNpdCBhbWV0IGFudGUgYWMsIHRpbmNpZHVudCBwb3J0dGl0b3IgbGFjdXMuIFZpdmFtdXMgZnJpbmdpbGxhLCBleCBlZ2V0IGNvbmd1ZSBkaWduaXNzaW0sIGVuaW0gbWF1cmlzIHRyaXN0aXF1ZSBmZWxpcywgc2l0IGFtZXQgbGFvcmVldCBsaWJlcm8gbnVsbGEgZWdldCBwdXJ1cy4gTnVsbGEgZmFjaWxpc2kuIFN1c3BlbmRpc3NlIGRvbG9yIHB1cnVzLCBtYWxlc3VhZGEgc2l0IGFtZXQgbWFnbmEgYXQsIHZ1bHB1dGF0ZSBsYW9yZWV0IGFyY3UuIFZlc3RpYnVsdW0gaWFjdWxpcyBuaWJoIGEgdmVsaXQgaW1wZXJkaWV0LCBpZCBydXRydW0gdHVycGlzIHNjZWxlcmlzcXVlLiBQaGFzZWxsdXMgbGFvcmVldCBzYXBpZW4gbm9uIHJ1dHJ1bSByaG9uY3VzLiBFdGlhbSBmcmluZ2lsbGEgYXQgZXJhdCBuZWMgbW9sbGlzLiBTdXNwZW5kaXNzZSB2aXZlcnJhIHBvc3VlcmUgZHVpLiBFdGlhbSBlbGVpZmVuZCBzb2xsaWNpdHVkaW4gdXJuYSwgaW4gdGVtcHVzIGZlbGlzLiBJbnRlZ2VyIG1hbGVzdWFkYSBzb2RhbGVzIGxvcmVtIHZlbCBjb25kaW1lbnR1bS4gUGhhc2VsbHVzIG1hbGVzdWFkYSB0aW5jaWR1bnQgc2VtIGluIGJsYW5kaXQuIEZ1c2NlIG5vbiBtb2xsaXMgc2FwaWVuLiBVdCBpZCBkaWN0dW0gbGVjdHVzLCBlZ2V0IGFjY3Vtc2FuIHJpc3VzLiBNYXVyaXMgc2VkIHZpdmVycmEgbGlndWxhLCBhIGVnZXN0YXMgbmVxdWUuIFByYWVzZW50IGNvbnNlcXVhdCBtYXNzYSB2ZWwgdnVscHV0YXRlIGVmZmljaXR1ci4gQ3VyYWJpdHVyIHNlbXBlciwgZXJvcyBlZ2V0IHBlbGxlbnRlc3F1ZSBhbGlxdWV0LCBzZW0gbWFzc2Egc2NlbGVyaXNxdWUgbmlzbCwgaWQgY29uc2VxdWF0IGVsaXQgbWFzc2Egc2l0IGFtZXQgbGVjdHVzLiBEb25lYyBmYWNpbGlzaXMgY29udmFsbGlzIGNvbW1vZG8uIFBoYXNlbGx1cyB0cmlzdGlxdWUgdGVtcG9yIGxvcmVtLCBkaWN0dW0gdWxsYW1jb3JwZXIgZmVsaXMgZWxlbWVudHVtIGV1LiBOdW5jIGEgbGlndWxhIHNlZCBvcmNpIGJpYmVuZHVtIG1heGltdXMuIE51bGxhbSBmYWNpbGlzaXMgc2VtcGVyIHRvcnRvciBldSBmcmluZ2lsbGEuIEFsaXF1YW0gbmVjIHB1bHZpbmFyIHRlbGx1cy4gVml2YW11cyBwdWx2aW5hciBsZW8gbGVjdHVzLCB2ZWwgZGlnbmlzc2ltIGxlbyBzYWdpdHRpcyBhdC4gUXVpc3F1ZSBkYXBpYnVzIG1hdXJpcyBzZWQgbnVuYyBmYWNpbGlzaXMsIGEgbWF0dGlzIHB1cnVzIHZlbmVuYXRpcy4gVml2YW11cyB1dCBpbnRlcmR1bSBsZW8sIGEgaW50ZXJkdW0gZWxpdC4gTmFtIG1heGltdXMgcG9ydHRpdG9yIGxpYmVybyBuZWMgcG9zdWVyZS4gSW50ZWdlciBkaWFtIG9kaW8sIGlhY3VsaXMgdXQgZW5pbSBlZ2V0LCBwb3J0dGl0b3IgdnVscHV0YXRlIGRpYW0uIE1vcmJpIGV1IG5lcXVlIHJpc3VzLiBDdXJhYml0dXIgZmVybWVudHVtIGF0IGxhY3VzIG5lYyBwb3J0dGl0b3IuIEludGVnZXIgZXQgbWFzc2Egdml0YWUgbWF1cmlzIHByZXRpdW0gdHJpc3RpcXVlIGV1IGF0IG5pc2kuIE5hbSBhdCBkYXBpYnVzIG5pc2kuIEZ1c2NlIGRpZ25pc3NpbSBpcHN1bSBzaXQgYW1ldCBhdWd1ZSBtb2xlc3RpZSBkYXBpYnVzLiBVdCBzYXBpZW4gbWF1cmlzLCBsYW9yZWV0IHNlZCBtYWduYSBlZ2V0LCBoZW5kcmVyaXQgdWxsYW1jb3JwZXIgbGVjdHVzLiBDcmFzIG1vbGVzdGllIG51bmMgcXVpcyB2ZXN0aWJ1bHVtIHNhZ2l0dGlzLiBRdWlzcXVlIHF1aXMgdmVzdGlidWx1bSByaXN1cy4gQWVuZWFuIHV0IG1hZ25hIGluIGVyb3MgbWFsZXN1YWRhIHNjZWxlcmlzcXVlLiBTZWQgZmV1Z2lhdCBmZXJtZW50dW0gbmlzaSBzZWQgZmF1Y2lidXMuIE51bGxhbSBhdCBsb2JvcnRpcyB1cm5hLiBQaGFzZWxsdXMgZGljdHVtIGVzdCBkaWFtLCBxdWlzIHZvbHV0cGF0IHRvcnRvciBzb2RhbGVzIGluLiBTZWQgaW4gZXN0IGNvbW1vZG8sIGNvbmRpbWVudHVtIHJpc3VzIHF1aXMsIHNhZ2l0dGlzIGxhY3VzLiBRdWlzcXVlIHRpbmNpZHVudCBjb21tb2RvIHVybmEgYXQgbW9sZXN0aWUuIE51bGxhIGEgZGlhbSB0b3J0b3IuIE51bmMgdml2ZXJyYSBpcHN1bSBpZCBtYXVyaXMgc29sbGljaXR1ZGluIGlhY3VsaXMuIE51bGxhbSB2dWxwdXRhdGUgaGVuZHJlcml0IGVzdCBmYWNpbGlzaXMgZWZmaWNpdHVyLiBQcmFlc2VudCBsYWNpbmlhIGNvbnNlY3RldHVyIG9yY2ksIGVnZXQgZmVybWVudHVtIG1hZ25hIG1hdHRpcyBhdC4gQ3VyYWJpdHVyIHZpdGFlIGVsZWlmZW5kIHRlbGx1cywgc2VkIGx1Y3R1cyB1cm5hLiBOYW0gZWdlc3RhcyB2ZWxpdCB0ZWxsdXMuIENyYXMgYWMgYXVndWUgZGlhbS4gTnVsbGFtIHZlbCB0ZWxsdXMgZWxpdC4gRXRpYW0gbmlzaSBkaWFtLCBhdWN0b3IgdXQgZmVsaXMgZXUsIGZlcm1lbnR1bSB2b2x1dHBhdCBsaWd1bGEuIFBoYXNlbGx1cyBmYXVjaWJ1cyBjb25kaW1lbnR1bSBwaGFyZXRyYS4gTmFtIGV1IG51bmMgc2VkIHRvcnRvciBwZWxsZW50ZXNxdWUgZWxlbWVudHVtLiBOYW0gbWF4aW11cyBqdXN0byBldSBpcHN1bSBkaWN0dW0sIGVnZXQgc29kYWxlcyBsb3JlbSB2ZWhpY3VsYS4gQWVuZWFuIGZhY2lsaXNpcyBuZXF1ZSB2ZWwgb3JuYXJlIGludGVyZHVtLiBTZWQgYWNjdW1zYW4gbmlzbCBtb2xlc3RpZSB2ZWxpdCBpbnRlcmR1bSwgbmVjIHNhZ2l0dGlzIGVyb3MgY29uZ3VlLiBQcm9pbiB2YXJpdXMgYXVndWUgdml0YWUgZW5pbSBkYXBpYnVzLCBlZ2V0IHRyaXN0aXF1ZSBqdXN0byBkaWN0dW0uIE1hZWNlbmFzIGJpYmVuZHVtIHF1YW0gZXUgdmFyaXVzIHNlbXBlci4gVml2YW11cyBlZmZpY2l0dXIganVzdG8gYSB2YXJpdXMgbWF4aW11cy4gRG9uZWMgbm9uIGlwc3VtIGx1Y3R1cywgb3JuYXJlIG5pYmggbmVjLCBmZXJtZW50dW0gbGlndWxhLiBVdCBpZCBwbGFjZXJhdCBsZW8uIEN1cmFiaXR1ciBmZXVnaWF0IG1hdHRpcyBjb25ndWUuIFN1c3BlbmRpc3NlIHRpbmNpZHVudCBmZWxpcyB0ZW1wdXMsIG1vbGxpcyBzYXBpZW4gbm9uLCByaG9uY3VzIGF1Z3VlLiBWZXN0aWJ1bHVtIG5vbiBwdWx2aW5hciBvcmNpLiBTZWQgdGVtcHVzIG5vbiBsb3JlbSBldCBmZXVnaWF0LiBDdXJhYml0dXIgdWx0cmljaWVzIHNlZCBuaXNpIGFjIGVmZmljaXR1ci4gRHVpcyBwZWxsZW50ZXNxdWUsIG1ldHVzIGVnZXQgbWFsZXN1YWRhIHNvZGFsZXMsIG5lcXVlIG9yY2kgdmVzdGlidWx1bSBhdWd1ZSwgbm9uIHByZXRpdW0gYXVndWUgZXN0IGFjIGVuaW0uIFByb2luIGVnZXN0YXMsIHF1YW0gcXVpcyB0aW5jaWR1bnQgc29kYWxlcywgaXBzdW0gbWF1cmlzIGNvbmd1ZSB0dXJwaXMsIGFjIHJob25jdXMgZW5pbSBqdXN0byBhYyB1cm5hLiBTdXNwZW5kaXNzZSBwb3RlbnRpLiBQcmFlc2VudCBhYyBlcm9zIHZpdGFlIGxhY3VzIHJ1dHJ1bSBlZmZpY2l0dXIuIEFsaXF1YW0gYXQgdGluY2lkdW50IG51bmMuIFF1aXNxdWUgcG9zdWVyZSBtYXVyaXMgbmVjIGxpYmVybyB2ZW5lbmF0aXMgdmVoaWN1bGEuIFBlbGxlbnRlc3F1ZSBzb2xsaWNpdHVkaW4gaW50ZXJkdW0gY29tbW9kby4gTWF1cmlzIGhlbmRyZXJpdCBhbGlxdWFtIG5lcXVlIGlkIGZhdWNpYnVzLiBFdGlhbSBtYXhpbXVzIHRlbGx1cyBhbGlxdWV0IG5pc2wgdGVtcG9yIG1hdHRpcy4gU3VzcGVuZGlzc2UgcG90ZW50aS4gQWVuZWFuIGRpZ25pc3NpbSBpYWN1bGlzIGZlcm1lbnR1bS4gUHJvaW4gdGVsbHVzIGVuaW0sIGRpY3R1bSBlZ2V0IGZldWdpYXQgZXQsIHNvbGxpY2l0dWRpbiBldSBsb3JlbS4gRG9uZWMgZGlnbmlzc2ltIHRlbXBvciBxdWFtIHF1aXMgbHVjdHVzLiBTZWQgb2RpbyBsZW8sIGZhdWNpYnVzIGluIHB1cnVzIHF1aXMsIHRlbXB1cyBsb2JvcnRpcyBkb2xvci4gSW50ZWdlciBzaXQgYW1ldCB2dWxwdXRhdGUgZHVpLiBQcmFlc2VudCB1cm5hIGlwc3VtLCBoZW5kcmVyaXQgaWQgZXJvcyBuZWMsIGZyaW5naWxsYSBtYXR0aXMgb3JjaS4gTW9yYmkgdXQgaWFjdWxpcyBuaXNsLCBuZWMgaWFjdWxpcyBudW5jLiBDbGFzcyBhcHRlbnQgdGFjaXRpIHNvY2lvc3F1IGFkIGxpdG9yYSB0b3JxdWVudCBwZXIgY29udWJpYSBub3N0cmEsIHBlciBpbmNlcHRvcyBoaW1lbmFlb3MuIE5hbSB1dCBsaWd1bGEgbm9uIHRlbGx1cyBlbGVpZmVuZCBpYWN1bGlzIGV1IHZlbCBxdWFtLiBTZWQgdHVycGlzIGlwc3VtLCBjb21tb2RvIG5lYyBqdXN0byBhYywgc29sbGljaXR1ZGluIHNjZWxlcmlzcXVlIGF1Z3VlLiBTZWQgZWdldCBlcm9zIG1heGltdXMsIGNvbW1vZG8gZWxpdCB2aXRhZSwgYmxhbmRpdCBudW5jLiBDdXJhYml0dXIgYXVjdG9yIHZhcml1cyBpcHN1bSBzaXQgYW1ldCBlZ2VzdGFzLiBTdXNwZW5kaXNzZSBwdXJ1cyBkb2xvciwgdmVuZW5hdGlzIGluIGFyY3UgY29uZ3VlLCB1bGxhbWNvcnBlciBkYXBpYnVzIG1hc3NhLiBNYWVjZW5hcyBhIHF1YW0gYWNjdW1zYW4sIGNvbmRpbWVudHVtIGp1c3RvIHF1aXMsIHBvcnR0aXRvciBuaWJoLiBDdXJhYml0dXIgZXggZXJhdCwgcGVsbGVudGVzcXVlIG5lYyBtYXNzYSBpbiwgcnV0cnVtIG9ybmFyZSBsZWN0dXM=\",\"algorithm\":\"aa-ed25519\"}", 
	);

    // Random rust generated tests.
    aa_manual_test(
        "{\"private_key\":\"wr4CbI5pEBXn0DKX0IujzVdXzq1YvsqYA77kngVXZP5zHpQF6WjywdarR2EUL2rMbYopffBy_GJzF2S2_PAiPA==\",\"algorithm\":\"aa-ed25519\"}",
        "{\"public_key\":\"cx6UBelo8sHWq0dhFC9qzG2KKX3wcvxicxdktvzwIjw=\",\"algorithm\":\"aa-ed25519\"}",
        hex_to_u8( "21A17E77EF0BB6739F46C83105B1E8ACB1D5D921B5519A63BAF1936BF5CBAD5A631E320AB43976C1533B6926147F135DDFC95B96C94699CC5A4412ECC91EBB9DCB33922912B7F211A9B04F9D9E65705878CADAEE16750373BF7F56ED1D2EFA1F52D238EDAD9D4D57C0A976DE55017322CD7423E5DD8A3EC7E0AC9140C04D2B3A3A9A84844152B826866D0BA8747083BD91E3A0624E7C0A6219EF59BC266BB01DB72910B1B73C7F31179347DB965DCB75EB0203A1FC8AEF69E12FF2FA389F4B7C638FD505A0FB576580BED9960FD45CD861DC2FEBABC0639C6E178FD55DC3320701A1FDB9E1701DF9F1A0089CB6FF8A41EEEAA2CEE5B31239967EB559CF505062"),
        "{\"content\":\"IaF-d-8LtnOfRsgxBbHorLHV2SG1UZpjuvGTa_XLrVpjHjIKtDl2wVM7aSYUfxNd38lblslGmcxaRBLsyR67ncszkikSt_IRqbBPnZ5lcFh4ytruFnUDc79_Vu0dLvofUtI47a2dTVfAqXbeVQFzIs10I-Xdij7H4KyRQMBNKzo6moSEQVK4JoZtC6h0cIO9keOgYk58CmIZ71m8JmuwHbcpELG3PH8xF5NH25Zdy3XrAgOh_IrvaeEv8vo4n0t8Y4_VBaD7V2WAvtmWD9Rc2GHcL-urwGOcbheP1V3DMgcBof254XAd-fGgCJy2_4pB7uqizuWzEjmWfrVZz1BQYg==\",\"signature\":\"AaRQ5_jb93GzKP7QWy9A6a8OnQ34siMx2_VqPV7tXBmEL5pm6IRTX4xiTV8Iq3uPcGK7HR7f-GOfpGrDghDyDA==\",\"identifier\":\"P2r6amLrhX8xMEGiz7VzjguiPeSJUnisc\",\"algorithm\":\"aa-ed25519\"}"
        );

    aa_manual_test(
        "{\"private_key\":\"3Fqq3li8LjjsVcH5stioNiTf6PGllvVP6X3_iZCOBtFj1ewdBpjgaddFWAcDNP701qcixoCzZ4SfO6T-1shbsQ==\",\"algorithm\":\"aa-ed25519\"}",
        "{\"public_key\":\"Y9XsHQaY4GnXRVgHAzT-9NanIsaAs2eEnzuk_tbIW7E=\",\"algorithm\":\"aa-ed25519\"}",
        hex_to_u8( "8FAD1A84C94AB100262DAE23995551EF9860BFEF66A5D9CDC0214EE4244045C7F9AF1EBBC434C719B10F5EC466591EE172557C3E410219E2FD5BF63803A474C9A5F8E46E69DB1408DDEA5FF2D9DBDB64636679D2E3042FFDCDD469A6D03D25C872E7AC150F1837F8F1E02D959A88B0E06F74E4F148792589AE545F3E95EEC9F45AABD37AF1C71398F38BBDBD32B8E77A59D559BA8F25E876C67FF1DB3AAC66C7A82EA6AC47F3B4C08A126B120F113A07FC3E370236040B19C503694E7B820F30F8B16018686DCE3872F7462B6399EB2F28164493F6D82C9C4883C70BF3BD0E3421B520954C7FDCDDA74FCA828A8CA6273A53765229DAF30B0E6804E4666E04B7"),
        "{\"content\":\"j60ahMlKsQAmLa4jmVVR75hgv-9mpdnNwCFO5CRARcf5rx67xDTHGbEPXsRmWR7hclV8PkECGeL9W_Y4A6R0yaX45G5p2xQI3epf8tnb22RjZnnS4wQv_c3UaabQPSXIcuesFQ8YN_jx4C2Vmoiw4G905PFIeSWJrlRfPpXuyfRaq9N68ccTmPOLvb0yuOd6WdVZuo8l6HbGf_HbOqxmx6gupqxH87TAihJrEg8ROgf8PjcCNgQLGcUDaU57gg8w-LFgGGhtzjhy90YrY5nrLygWRJP22CycSIPHC_O9DjQhtSCVTH_c3adPyoKKjKYnOlN2Uina8wsOaATkZm4Etw==\",\"signature\":\"Ji-XjnoWMp8SS0Y9sCVc3ZkDsHsQ1xuWILXfRCdrHRAKNGohH4pUSVVS2PYFWBz2f1pIc0GlOhZj383PsJj_DA==\",\"identifier\":\"Hm6d7pDvNqJJD8A57B4d6vTNyjmbgFNhz\",\"algorithm\":\"aa-ed25519\"}"
        );
}

