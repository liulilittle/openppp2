#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseAction {
    HideToTray,
    Exit,
}

pub fn close_action(close_to_tray: bool, exit_requested: bool) -> CloseAction {
    if close_to_tray && !exit_requested {
        CloseAction::HideToTray
    } else {
        CloseAction::Exit
    }
}

pub fn should_disconnect_on_exit(disconnect_on_exit: bool) -> bool {
    disconnect_on_exit
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrayPrimaryAction {
    Connect(String),
    Disconnect,
    ShowWindow,
}

pub fn tray_primary_action(running: bool, last_node_id: Option<&str>) -> TrayPrimaryAction {
    if running {
        TrayPrimaryAction::Disconnect
    } else if let Some(node_id) = last_node_id {
        TrayPrimaryAction::Connect(node_id.to_owned())
    } else {
        TrayPrimaryAction::ShowWindow
    }
}
