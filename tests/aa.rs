extern crate pkauth;
extern crate ring;
extern crate serde_json;

use pkauth::{ToPublicKey};
use pkauth::asym::auth as aa;
use pkauth::{PKAJ};
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
        // let key = serde_json::to_vec( &key).unwrap();
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

#[test]
fn aa_manual_tests() {
	aa_manual_test(
		"{\"algorithm\":\"auth-ed25519\",\"private_key\":\"Jg0dbvyT9LImDR1u_JP0siYNHW78k_SyJg0dbvyT9LJ8FYC5TgtSnlxHYfo-v_aXpBabatIlDzJw87eTjUL_yw==\"}",
		"{\"public_key\":\"fBWAuU4LUp5cR2H6Pr_2l6QWm2rSJQ8ycPO3k41C_8s=\",\"algorithm\":\"auth-ed25519\"}", 
		"".to_owned().into_bytes(),
		"{\"signature\":\"zxW1qxudeD5nprRf5xMhC_FNAlIEQmtB7KPXnZzonIZu6miywsCLuCxSU6vxIryulqDRbZinL5yvAGcPEk7bDQ==\",\"identifier\":\"8ZsJKn2QSMjQyssExb7KZzK9VK5qryExz\",\"content\":\"\",\"algorithm\":\"auth-ed25519\"}"
	); 
	aa_manual_test(
		"{\"algorithm\":\"auth-ed25519\",\"private_key\":\"Jg0dbvyT9LImDR1u_JP0siYNHW78k_SyJg0dbvyT9LJ8FYC5TgtSnlxHYfo-v_aXpBabatIlDzJw87eTjUL_yw==\"}",
		"{\"public_key\":\"fBWAuU4LUp5cR2H6Pr_2l6QWm2rSJQ8ycPO3k41C_8s=\",\"algorithm\":\"auth-ed25519\"}", 
		"shelled pistachios".to_owned().into_bytes(),
 
		"{\"signature\":\"ZG4XAMOu16WZrASwn7ADwzYBzH4nXnjF7WUBZEzVh8V5XPKZvlx0SlabG4iuivrghHaaw2Bc2Z8rqKQy8c93AQ==\",\"identifier\":\"8ZsJKn2QSMjQyssExb7KZzK9VK5qryExz\",\"content\":\"c2hlbGxlZCBwaXN0YWNoaW9z\",\"algorithm\":\"auth-ed25519\"}"
	); 
	aa_manual_test(
		"{\"algorithm\":\"auth-ed25519\",\"private_key\":\"Gi-kD64CwTYaL6QPrgLBNhovpA-uAsE2Gi-kD64CwTZvwNWsATeieamFLzovnITWQ4a4wt2iBoi4hFbkRmZXmg==\"}", 
		"{\"public_key\":\"b8DVrAE3onmphS86L5yE1kOGuMLdogaIuIRW5EZmV5o=\",\"algorithm\":\"auth-ed25519\"}",
		"Haribo Gold-bears".to_owned().into_bytes(),

		"{\"signature\":\"ElnnndP57CZZApMq1c8hiZ5Vze45vjbOD1CPFAoibhIv1yN0l2MErM8p6nyWXnZDiHkP6WMirJGIX1OLX0MRCQ==\",\"identifier\":\"MijeyEWKvcciSvDCd3k1rxEbmQXtcgMRs\",\"content\":\"SGFyaWJvIEdvbGQtYmVhcnM=\",\"algorithm\":\"auth-ed25519\"}"
	); 
	aa_manual_test(
		"{\"algorithm\":\"auth-ed25519\",\"private_key\":\"Gi-kD64CwTYaL6QPrgLBNhovpA-uAsE2Gi-kD64CwTZvwNWsATeieamFLzovnITWQ4a4wt2iBoi4hFbkRmZXmg==\"}", 
		"{\"public_key\":\"b8DVrAE3onmphS86L5yE1kOGuMLdogaIuIRW5EZmV5o=\",\"algorithm\":\"auth-ed25519\"}",
		vec![0x0A, 0x20, 0x0B, 0x20, 0xDE, 0x20, 0xAD, 0x20, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x20, 0xFF, 0x20, 0xFF, 0x20, 0x00],
		"{\"signature\":\"EYO-liRbTrup7LuFWCaF77pD36si-oSH92K4bIlNtFsBZW6rhJOEWh2Zjg9pQpIvM_grFTXL0dXel9iImwNeCQ==\",\"identifier\":\"MijeyEWKvcciSvDCd3k1rxEbmQXtcgMRs\",\"content\":\"CiALIN4grSAqKioqKioqKioqKioqKiD_IP8gAA==\",\"algorithm\":\"auth-ed25519\"}"
	); 

	aa_manual_test(
		"{\"algorithm\":\"auth-ed25519\",\"private_key\":\"Gi-kD64CwTYaL6QPrgLBNhovpA-uAsE2Gi-kD64CwTZvwNWsATeieamFLzovnITWQ4a4wt2iBoi4hFbkRmZXmg==\"}", 
		"{\"public_key\":\"b8DVrAE3onmphS86L5yE1kOGuMLdogaIuIRW5EZmV5o=\",\"algorithm\":\"auth-ed25519\"}",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce quis diam vehicula, scelerisque felis ac, vehicula justo. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Fusce ullamcorper gravida metus non vestibulum. Aliquam accumsan elit nec mauris tincidunt suscipit. Donec nec bibendum nunc, et venenatis arcu. In malesuada sagittis rutrum. Aenean sit amet mi quis ante fermentum venenatis. Cras rhoncus interdum porttitor. Nam at imperdiet justo. Vivamus venenatis lacinia elit in auctor. Duis tincidunt scelerisque risus in iaculis. Nunc facilisis eros eu pellentesque ultrices. Nullam eget cursus tortor, vulputate aliquet sapien. Aenean gravida ullamcorper justo, in faucibus nisi ultrices ac. Morbi feugiat ante eget rutrum imperdiet. Duis at posuere risus, sed maximus turpis. Sed eget lobortis sapien. Cras porttitor, nulla et tempor sollicitudin, nibh est mattis ex, imperdiet ultrices lacus sapien et tellus. Donec quis dui auctor, imperdiet libero nec, iaculis mauris. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Donec ornare ipsum sed diam ultrices, eget fermentum augue accumsan. Curabitur eros nisi, venenatis lobortis neque vel, luctus efficitur nibh. Mauris eu maximus purus. Phasellus consequat odio commodo justo faucibus, eu rutrum diam facilisis. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Fusce egestas feugiat nunc nec faucibus. Aenean nisl diam, ullamcorper sit amet ante ac, tincidunt porttitor lacus. Vivamus fringilla, ex eget congue dignissim, enim mauris tristique felis, sit amet laoreet libero nulla eget purus. Nulla facilisi. Suspendisse dolor purus, malesuada sit amet magna at, vulputate laoreet arcu. Vestibulum iaculis nibh a velit imperdiet, id rutrum turpis scelerisque. Phasellus laoreet sapien non rutrum rhoncus. Etiam fringilla at erat nec mollis. Suspendisse viverra posuere dui. Etiam eleifend sollicitudin urna, in tempus felis. Integer malesuada sodales lorem vel condimentum. Phasellus malesuada tincidunt sem in blandit. Fusce non mollis sapien. Ut id dictum lectus, eget accumsan risus. Mauris sed viverra ligula, a egestas neque. Praesent consequat massa vel vulputate efficitur. Curabitur semper, eros eget pellentesque aliquet, sem massa scelerisque nisl, id consequat elit massa sit amet lectus. Donec facilisis convallis commodo. Phasellus tristique tempor lorem, dictum ullamcorper felis elementum eu. Nunc a ligula sed orci bibendum maximus. Nullam facilisis semper tortor eu fringilla. Aliquam nec pulvinar tellus. Vivamus pulvinar leo lectus, vel dignissim leo sagittis at. Quisque dapibus mauris sed nunc facilisis, a mattis purus venenatis. Vivamus ut interdum leo, a interdum elit. Nam maximus porttitor libero nec posuere. Integer diam odio, iaculis ut enim eget, porttitor vulputate diam. Morbi eu neque risus. Curabitur fermentum at lacus nec porttitor. Integer et massa vitae mauris pretium tristique eu at nisi. Nam at dapibus nisi. Fusce dignissim ipsum sit amet augue molestie dapibus. Ut sapien mauris, laoreet sed magna eget, hendrerit ullamcorper lectus. Cras molestie nunc quis vestibulum sagittis. Quisque quis vestibulum risus. Aenean ut magna in eros malesuada scelerisque. Sed feugiat fermentum nisi sed faucibus. Nullam at lobortis urna. Phasellus dictum est diam, quis volutpat tortor sodales in. Sed in est commodo, condimentum risus quis, sagittis lacus. Quisque tincidunt commodo urna at molestie. Nulla a diam tortor. Nunc viverra ipsum id mauris sollicitudin iaculis. Nullam vulputate hendrerit est facilisis efficitur. Praesent lacinia consectetur orci, eget fermentum magna mattis at. Curabitur vitae eleifend tellus, sed luctus urna. Nam egestas velit tellus. Cras ac augue diam. Nullam vel tellus elit. Etiam nisi diam, auctor ut felis eu, fermentum volutpat ligula. Phasellus faucibus condimentum pharetra. Nam eu nunc sed tortor pellentesque elementum. Nam maximus justo eu ipsum dictum, eget sodales lorem vehicula. Aenean facilisis neque vel ornare interdum. Sed accumsan nisl molestie velit interdum, nec sagittis eros congue. Proin varius augue vitae enim dapibus, eget tristique justo dictum. Maecenas bibendum quam eu varius semper. Vivamus efficitur justo a varius maximus. Donec non ipsum luctus, ornare nibh nec, fermentum ligula. Ut id placerat leo. Curabitur feugiat mattis congue. Suspendisse tincidunt felis tempus, mollis sapien non, rhoncus augue. Vestibulum non pulvinar orci. Sed tempus non lorem et feugiat. Curabitur ultricies sed nisi ac efficitur. Duis pellentesque, metus eget malesuada sodales, neque orci vestibulum augue, non pretium augue est ac enim. Proin egestas, quam quis tincidunt sodales, ipsum mauris congue turpis, ac rhoncus enim justo ac urna. Suspendisse potenti. Praesent ac eros vitae lacus rutrum efficitur. Aliquam at tincidunt nunc. Quisque posuere mauris nec libero venenatis vehicula. Pellentesque sollicitudin interdum commodo. Mauris hendrerit aliquam neque id faucibus. Etiam maximus tellus aliquet nisl tempor mattis. Suspendisse potenti. Aenean dignissim iaculis fermentum. Proin tellus enim, dictum eget feugiat et, sollicitudin eu lorem. Donec dignissim tempor quam quis luctus. Sed odio leo, faucibus in purus quis, tempus lobortis dolor. Integer sit amet vulputate dui. Praesent urna ipsum, hendrerit id eros nec, fringilla mattis orci. Morbi ut iaculis nisl, nec iaculis nunc. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Nam ut ligula non tellus eleifend iaculis eu vel quam. Sed turpis ipsum, commodo nec justo ac, sollicitudin scelerisque augue. Sed eget eros maximus, commodo elit vitae, blandit nunc. Curabitur auctor varius ipsum sit amet egestas. Suspendisse purus dolor, venenatis in arcu congue, ullamcorper dapibus massa. Maecenas a quam accumsan, condimentum justo quis, porttitor nibh. Curabitur ex erat, pellentesque nec massa in, rutrum ornare lectus".to_owned().into_bytes(), 
		"{\"signature\":\"wB4waBKpwXVf_LEfimQ5NjgXjx4rIBxoWyQutG2-sBoclHAKDU2QQDJnHVqxB67BN35bnpLVHo7NB011oWWFCA==\",\"identifier\":\"MijeyEWKvcciSvDCd3k1rxEbmQXtcgMRs\",\"content\":\"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gRnVzY2UgcXVpcyBkaWFtIHZlaGljdWxhLCBzY2VsZXJpc3F1ZSBmZWxpcyBhYywgdmVoaWN1bGEganVzdG8uIENsYXNzIGFwdGVudCB0YWNpdGkgc29jaW9zcXUgYWQgbGl0b3JhIHRvcnF1ZW50IHBlciBjb251YmlhIG5vc3RyYSwgcGVyIGluY2VwdG9zIGhpbWVuYWVvcy4gRnVzY2UgdWxsYW1jb3JwZXIgZ3JhdmlkYSBtZXR1cyBub24gdmVzdGlidWx1bS4gQWxpcXVhbSBhY2N1bXNhbiBlbGl0IG5lYyBtYXVyaXMgdGluY2lkdW50IHN1c2NpcGl0LiBEb25lYyBuZWMgYmliZW5kdW0gbnVuYywgZXQgdmVuZW5hdGlzIGFyY3UuIEluIG1hbGVzdWFkYSBzYWdpdHRpcyBydXRydW0uIEFlbmVhbiBzaXQgYW1ldCBtaSBxdWlzIGFudGUgZmVybWVudHVtIHZlbmVuYXRpcy4gQ3JhcyByaG9uY3VzIGludGVyZHVtIHBvcnR0aXRvci4gTmFtIGF0IGltcGVyZGlldCBqdXN0by4gVml2YW11cyB2ZW5lbmF0aXMgbGFjaW5pYSBlbGl0IGluIGF1Y3Rvci4gRHVpcyB0aW5jaWR1bnQgc2NlbGVyaXNxdWUgcmlzdXMgaW4gaWFjdWxpcy4gTnVuYyBmYWNpbGlzaXMgZXJvcyBldSBwZWxsZW50ZXNxdWUgdWx0cmljZXMuIE51bGxhbSBlZ2V0IGN1cnN1cyB0b3J0b3IsIHZ1bHB1dGF0ZSBhbGlxdWV0IHNhcGllbi4gQWVuZWFuIGdyYXZpZGEgdWxsYW1jb3JwZXIganVzdG8sIGluIGZhdWNpYnVzIG5pc2kgdWx0cmljZXMgYWMuIE1vcmJpIGZldWdpYXQgYW50ZSBlZ2V0IHJ1dHJ1bSBpbXBlcmRpZXQuIER1aXMgYXQgcG9zdWVyZSByaXN1cywgc2VkIG1heGltdXMgdHVycGlzLiBTZWQgZWdldCBsb2JvcnRpcyBzYXBpZW4uIENyYXMgcG9ydHRpdG9yLCBudWxsYSBldCB0ZW1wb3Igc29sbGljaXR1ZGluLCBuaWJoIGVzdCBtYXR0aXMgZXgsIGltcGVyZGlldCB1bHRyaWNlcyBsYWN1cyBzYXBpZW4gZXQgdGVsbHVzLiBEb25lYyBxdWlzIGR1aSBhdWN0b3IsIGltcGVyZGlldCBsaWJlcm8gbmVjLCBpYWN1bGlzIG1hdXJpcy4gVmVzdGlidWx1bSBhbnRlIGlwc3VtIHByaW1pcyBpbiBmYXVjaWJ1cyBvcmNpIGx1Y3R1cyBldCB1bHRyaWNlcyBwb3N1ZXJlIGN1YmlsaWEgQ3VyYWU7IERvbmVjIG9ybmFyZSBpcHN1bSBzZWQgZGlhbSB1bHRyaWNlcywgZWdldCBmZXJtZW50dW0gYXVndWUgYWNjdW1zYW4uIEN1cmFiaXR1ciBlcm9zIG5pc2ksIHZlbmVuYXRpcyBsb2JvcnRpcyBuZXF1ZSB2ZWwsIGx1Y3R1cyBlZmZpY2l0dXIgbmliaC4gTWF1cmlzIGV1IG1heGltdXMgcHVydXMuIFBoYXNlbGx1cyBjb25zZXF1YXQgb2RpbyBjb21tb2RvIGp1c3RvIGZhdWNpYnVzLCBldSBydXRydW0gZGlhbSBmYWNpbGlzaXMuIFZlc3RpYnVsdW0gYW50ZSBpcHN1bSBwcmltaXMgaW4gZmF1Y2lidXMgb3JjaSBsdWN0dXMgZXQgdWx0cmljZXMgcG9zdWVyZSBjdWJpbGlhIEN1cmFlOyBGdXNjZSBlZ2VzdGFzIGZldWdpYXQgbnVuYyBuZWMgZmF1Y2lidXMuIEFlbmVhbiBuaXNsIGRpYW0sIHVsbGFtY29ycGVyIHNpdCBhbWV0IGFudGUgYWMsIHRpbmNpZHVudCBwb3J0dGl0b3IgbGFjdXMuIFZpdmFtdXMgZnJpbmdpbGxhLCBleCBlZ2V0IGNvbmd1ZSBkaWduaXNzaW0sIGVuaW0gbWF1cmlzIHRyaXN0aXF1ZSBmZWxpcywgc2l0IGFtZXQgbGFvcmVldCBsaWJlcm8gbnVsbGEgZWdldCBwdXJ1cy4gTnVsbGEgZmFjaWxpc2kuIFN1c3BlbmRpc3NlIGRvbG9yIHB1cnVzLCBtYWxlc3VhZGEgc2l0IGFtZXQgbWFnbmEgYXQsIHZ1bHB1dGF0ZSBsYW9yZWV0IGFyY3UuIFZlc3RpYnVsdW0gaWFjdWxpcyBuaWJoIGEgdmVsaXQgaW1wZXJkaWV0LCBpZCBydXRydW0gdHVycGlzIHNjZWxlcmlzcXVlLiBQaGFzZWxsdXMgbGFvcmVldCBzYXBpZW4gbm9uIHJ1dHJ1bSByaG9uY3VzLiBFdGlhbSBmcmluZ2lsbGEgYXQgZXJhdCBuZWMgbW9sbGlzLiBTdXNwZW5kaXNzZSB2aXZlcnJhIHBvc3VlcmUgZHVpLiBFdGlhbSBlbGVpZmVuZCBzb2xsaWNpdHVkaW4gdXJuYSwgaW4gdGVtcHVzIGZlbGlzLiBJbnRlZ2VyIG1hbGVzdWFkYSBzb2RhbGVzIGxvcmVtIHZlbCBjb25kaW1lbnR1bS4gUGhhc2VsbHVzIG1hbGVzdWFkYSB0aW5jaWR1bnQgc2VtIGluIGJsYW5kaXQuIEZ1c2NlIG5vbiBtb2xsaXMgc2FwaWVuLiBVdCBpZCBkaWN0dW0gbGVjdHVzLCBlZ2V0IGFjY3Vtc2FuIHJpc3VzLiBNYXVyaXMgc2VkIHZpdmVycmEgbGlndWxhLCBhIGVnZXN0YXMgbmVxdWUuIFByYWVzZW50IGNvbnNlcXVhdCBtYXNzYSB2ZWwgdnVscHV0YXRlIGVmZmljaXR1ci4gQ3VyYWJpdHVyIHNlbXBlciwgZXJvcyBlZ2V0IHBlbGxlbnRlc3F1ZSBhbGlxdWV0LCBzZW0gbWFzc2Egc2NlbGVyaXNxdWUgbmlzbCwgaWQgY29uc2VxdWF0IGVsaXQgbWFzc2Egc2l0IGFtZXQgbGVjdHVzLiBEb25lYyBmYWNpbGlzaXMgY29udmFsbGlzIGNvbW1vZG8uIFBoYXNlbGx1cyB0cmlzdGlxdWUgdGVtcG9yIGxvcmVtLCBkaWN0dW0gdWxsYW1jb3JwZXIgZmVsaXMgZWxlbWVudHVtIGV1LiBOdW5jIGEgbGlndWxhIHNlZCBvcmNpIGJpYmVuZHVtIG1heGltdXMuIE51bGxhbSBmYWNpbGlzaXMgc2VtcGVyIHRvcnRvciBldSBmcmluZ2lsbGEuIEFsaXF1YW0gbmVjIHB1bHZpbmFyIHRlbGx1cy4gVml2YW11cyBwdWx2aW5hciBsZW8gbGVjdHVzLCB2ZWwgZGlnbmlzc2ltIGxlbyBzYWdpdHRpcyBhdC4gUXVpc3F1ZSBkYXBpYnVzIG1hdXJpcyBzZWQgbnVuYyBmYWNpbGlzaXMsIGEgbWF0dGlzIHB1cnVzIHZlbmVuYXRpcy4gVml2YW11cyB1dCBpbnRlcmR1bSBsZW8sIGEgaW50ZXJkdW0gZWxpdC4gTmFtIG1heGltdXMgcG9ydHRpdG9yIGxpYmVybyBuZWMgcG9zdWVyZS4gSW50ZWdlciBkaWFtIG9kaW8sIGlhY3VsaXMgdXQgZW5pbSBlZ2V0LCBwb3J0dGl0b3IgdnVscHV0YXRlIGRpYW0uIE1vcmJpIGV1IG5lcXVlIHJpc3VzLiBDdXJhYml0dXIgZmVybWVudHVtIGF0IGxhY3VzIG5lYyBwb3J0dGl0b3IuIEludGVnZXIgZXQgbWFzc2Egdml0YWUgbWF1cmlzIHByZXRpdW0gdHJpc3RpcXVlIGV1IGF0IG5pc2kuIE5hbSBhdCBkYXBpYnVzIG5pc2kuIEZ1c2NlIGRpZ25pc3NpbSBpcHN1bSBzaXQgYW1ldCBhdWd1ZSBtb2xlc3RpZSBkYXBpYnVzLiBVdCBzYXBpZW4gbWF1cmlzLCBsYW9yZWV0IHNlZCBtYWduYSBlZ2V0LCBoZW5kcmVyaXQgdWxsYW1jb3JwZXIgbGVjdHVzLiBDcmFzIG1vbGVzdGllIG51bmMgcXVpcyB2ZXN0aWJ1bHVtIHNhZ2l0dGlzLiBRdWlzcXVlIHF1aXMgdmVzdGlidWx1bSByaXN1cy4gQWVuZWFuIHV0IG1hZ25hIGluIGVyb3MgbWFsZXN1YWRhIHNjZWxlcmlzcXVlLiBTZWQgZmV1Z2lhdCBmZXJtZW50dW0gbmlzaSBzZWQgZmF1Y2lidXMuIE51bGxhbSBhdCBsb2JvcnRpcyB1cm5hLiBQaGFzZWxsdXMgZGljdHVtIGVzdCBkaWFtLCBxdWlzIHZvbHV0cGF0IHRvcnRvciBzb2RhbGVzIGluLiBTZWQgaW4gZXN0IGNvbW1vZG8sIGNvbmRpbWVudHVtIHJpc3VzIHF1aXMsIHNhZ2l0dGlzIGxhY3VzLiBRdWlzcXVlIHRpbmNpZHVudCBjb21tb2RvIHVybmEgYXQgbW9sZXN0aWUuIE51bGxhIGEgZGlhbSB0b3J0b3IuIE51bmMgdml2ZXJyYSBpcHN1bSBpZCBtYXVyaXMgc29sbGljaXR1ZGluIGlhY3VsaXMuIE51bGxhbSB2dWxwdXRhdGUgaGVuZHJlcml0IGVzdCBmYWNpbGlzaXMgZWZmaWNpdHVyLiBQcmFlc2VudCBsYWNpbmlhIGNvbnNlY3RldHVyIG9yY2ksIGVnZXQgZmVybWVudHVtIG1hZ25hIG1hdHRpcyBhdC4gQ3VyYWJpdHVyIHZpdGFlIGVsZWlmZW5kIHRlbGx1cywgc2VkIGx1Y3R1cyB1cm5hLiBOYW0gZWdlc3RhcyB2ZWxpdCB0ZWxsdXMuIENyYXMgYWMgYXVndWUgZGlhbS4gTnVsbGFtIHZlbCB0ZWxsdXMgZWxpdC4gRXRpYW0gbmlzaSBkaWFtLCBhdWN0b3IgdXQgZmVsaXMgZXUsIGZlcm1lbnR1bSB2b2x1dHBhdCBsaWd1bGEuIFBoYXNlbGx1cyBmYXVjaWJ1cyBjb25kaW1lbnR1bSBwaGFyZXRyYS4gTmFtIGV1IG51bmMgc2VkIHRvcnRvciBwZWxsZW50ZXNxdWUgZWxlbWVudHVtLiBOYW0gbWF4aW11cyBqdXN0byBldSBpcHN1bSBkaWN0dW0sIGVnZXQgc29kYWxlcyBsb3JlbSB2ZWhpY3VsYS4gQWVuZWFuIGZhY2lsaXNpcyBuZXF1ZSB2ZWwgb3JuYXJlIGludGVyZHVtLiBTZWQgYWNjdW1zYW4gbmlzbCBtb2xlc3RpZSB2ZWxpdCBpbnRlcmR1bSwgbmVjIHNhZ2l0dGlzIGVyb3MgY29uZ3VlLiBQcm9pbiB2YXJpdXMgYXVndWUgdml0YWUgZW5pbSBkYXBpYnVzLCBlZ2V0IHRyaXN0aXF1ZSBqdXN0byBkaWN0dW0uIE1hZWNlbmFzIGJpYmVuZHVtIHF1YW0gZXUgdmFyaXVzIHNlbXBlci4gVml2YW11cyBlZmZpY2l0dXIganVzdG8gYSB2YXJpdXMgbWF4aW11cy4gRG9uZWMgbm9uIGlwc3VtIGx1Y3R1cywgb3JuYXJlIG5pYmggbmVjLCBmZXJtZW50dW0gbGlndWxhLiBVdCBpZCBwbGFjZXJhdCBsZW8uIEN1cmFiaXR1ciBmZXVnaWF0IG1hdHRpcyBjb25ndWUuIFN1c3BlbmRpc3NlIHRpbmNpZHVudCBmZWxpcyB0ZW1wdXMsIG1vbGxpcyBzYXBpZW4gbm9uLCByaG9uY3VzIGF1Z3VlLiBWZXN0aWJ1bHVtIG5vbiBwdWx2aW5hciBvcmNpLiBTZWQgdGVtcHVzIG5vbiBsb3JlbSBldCBmZXVnaWF0LiBDdXJhYml0dXIgdWx0cmljaWVzIHNlZCBuaXNpIGFjIGVmZmljaXR1ci4gRHVpcyBwZWxsZW50ZXNxdWUsIG1ldHVzIGVnZXQgbWFsZXN1YWRhIHNvZGFsZXMsIG5lcXVlIG9yY2kgdmVzdGlidWx1bSBhdWd1ZSwgbm9uIHByZXRpdW0gYXVndWUgZXN0IGFjIGVuaW0uIFByb2luIGVnZXN0YXMsIHF1YW0gcXVpcyB0aW5jaWR1bnQgc29kYWxlcywgaXBzdW0gbWF1cmlzIGNvbmd1ZSB0dXJwaXMsIGFjIHJob25jdXMgZW5pbSBqdXN0byBhYyB1cm5hLiBTdXNwZW5kaXNzZSBwb3RlbnRpLiBQcmFlc2VudCBhYyBlcm9zIHZpdGFlIGxhY3VzIHJ1dHJ1bSBlZmZpY2l0dXIuIEFsaXF1YW0gYXQgdGluY2lkdW50IG51bmMuIFF1aXNxdWUgcG9zdWVyZSBtYXVyaXMgbmVjIGxpYmVybyB2ZW5lbmF0aXMgdmVoaWN1bGEuIFBlbGxlbnRlc3F1ZSBzb2xsaWNpdHVkaW4gaW50ZXJkdW0gY29tbW9kby4gTWF1cmlzIGhlbmRyZXJpdCBhbGlxdWFtIG5lcXVlIGlkIGZhdWNpYnVzLiBFdGlhbSBtYXhpbXVzIHRlbGx1cyBhbGlxdWV0IG5pc2wgdGVtcG9yIG1hdHRpcy4gU3VzcGVuZGlzc2UgcG90ZW50aS4gQWVuZWFuIGRpZ25pc3NpbSBpYWN1bGlzIGZlcm1lbnR1bS4gUHJvaW4gdGVsbHVzIGVuaW0sIGRpY3R1bSBlZ2V0IGZldWdpYXQgZXQsIHNvbGxpY2l0dWRpbiBldSBsb3JlbS4gRG9uZWMgZGlnbmlzc2ltIHRlbXBvciBxdWFtIHF1aXMgbHVjdHVzLiBTZWQgb2RpbyBsZW8sIGZhdWNpYnVzIGluIHB1cnVzIHF1aXMsIHRlbXB1cyBsb2JvcnRpcyBkb2xvci4gSW50ZWdlciBzaXQgYW1ldCB2dWxwdXRhdGUgZHVpLiBQcmFlc2VudCB1cm5hIGlwc3VtLCBoZW5kcmVyaXQgaWQgZXJvcyBuZWMsIGZyaW5naWxsYSBtYXR0aXMgb3JjaS4gTW9yYmkgdXQgaWFjdWxpcyBuaXNsLCBuZWMgaWFjdWxpcyBudW5jLiBDbGFzcyBhcHRlbnQgdGFjaXRpIHNvY2lvc3F1IGFkIGxpdG9yYSB0b3JxdWVudCBwZXIgY29udWJpYSBub3N0cmEsIHBlciBpbmNlcHRvcyBoaW1lbmFlb3MuIE5hbSB1dCBsaWd1bGEgbm9uIHRlbGx1cyBlbGVpZmVuZCBpYWN1bGlzIGV1IHZlbCBxdWFtLiBTZWQgdHVycGlzIGlwc3VtLCBjb21tb2RvIG5lYyBqdXN0byBhYywgc29sbGljaXR1ZGluIHNjZWxlcmlzcXVlIGF1Z3VlLiBTZWQgZWdldCBlcm9zIG1heGltdXMsIGNvbW1vZG8gZWxpdCB2aXRhZSwgYmxhbmRpdCBudW5jLiBDdXJhYml0dXIgYXVjdG9yIHZhcml1cyBpcHN1bSBzaXQgYW1ldCBlZ2VzdGFzLiBTdXNwZW5kaXNzZSBwdXJ1cyBkb2xvciwgdmVuZW5hdGlzIGluIGFyY3UgY29uZ3VlLCB1bGxhbWNvcnBlciBkYXBpYnVzIG1hc3NhLiBNYWVjZW5hcyBhIHF1YW0gYWNjdW1zYW4sIGNvbmRpbWVudHVtIGp1c3RvIHF1aXMsIHBvcnR0aXRvciBuaWJoLiBDdXJhYml0dXIgZXggZXJhdCwgcGVsbGVudGVzcXVlIG5lYyBtYXNzYSBpbiwgcnV0cnVtIG9ybmFyZSBsZWN0dXM=\",\"algorithm\":\"auth-ed25519\"}", 
	);
}

