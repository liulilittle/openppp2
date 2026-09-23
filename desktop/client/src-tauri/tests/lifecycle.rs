use openppp2_client_desktop::lifecycle::{
    close_action, should_disconnect_on_exit, tray_primary_action, CloseAction, TrayPrimaryAction,
};

#[test]
fn close_request_hides_only_when_close_to_tray_is_enabled() {
    assert_eq!(close_action(true, false), CloseAction::HideToTray);
    assert_eq!(close_action(false, false), CloseAction::Exit);
    assert_eq!(close_action(true, true), CloseAction::Exit);
}

#[test]
fn explicit_exit_obeys_disconnect_preference() {
    assert!(should_disconnect_on_exit(true));
    assert!(!should_disconnect_on_exit(false));
}

#[test]
fn tray_primary_action_uses_runtime_and_last_node_state() {
    assert_eq!(
        tray_primary_action(true, Some("node-a")),
        TrayPrimaryAction::Disconnect
    );
    assert_eq!(
        tray_primary_action(false, Some("node-a")),
        TrayPrimaryAction::Connect("node-a".into())
    );
    assert_eq!(
        tray_primary_action(false, None),
        TrayPrimaryAction::ShowWindow
    );
}
