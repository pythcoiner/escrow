use async_hwi::ledger::{HidApi, Ledger, TransportHID};

#[allow(unused)]
fn list_devices() -> Vec<Ledger<TransportHID>> {
    let mut device_list: Vec<Ledger<TransportHID>> = Vec::new();

    let transport = Box::new(HidApi::new().unwrap());

    for detected in Ledger::<TransportHID>::enumerate(&transport) {
        if let Ok(device) = Ledger::<TransportHID>::connect(&transport, detected) {
            device_list.push(device);
        }
    }

    device_list
}
