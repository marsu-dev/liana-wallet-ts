use miniscript::bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
    Network,
};
use std::str::FromStr;

fn main() {
    let seed = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    let account = master.derive_priv(&secp, &DerivationPath::from_str("m/0'").unwrap()).unwrap();
    let account_xpub = Xpub::from_priv(&secp, &account);
    let testnet_master = Xpriv::new_master(Network::Testnet, &seed).unwrap();
    let signet_account = testnet_master
        .derive_priv(&secp, &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap())
        .unwrap();
    println!("tpub\t{}", Xpub::from_priv(&secp, &signet_account));
    for branch in 0..=1 {
        let path = DerivationPath::from(vec![branch.into(), 0.into()]);
        let child = account_xpub.derive_pub(&secp, &path).unwrap();
        let hex: String = child.public_key.serialize().iter().map(|byte| format!("{byte:02x}")).collect();
        println!("{branch}\t{hex}");
    }
}
