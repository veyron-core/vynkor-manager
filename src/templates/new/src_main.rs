use vynkor_sdk::proto::{envelope, ActionResponse, ActionStatus, Envelope, PluginManifest};
use vynkor_sdk::{Plugin, VynkorClient, VynkorError};

struct App;

impl Plugin for App {
    fn id(&self) -> &str {
        "{{name}}"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            actions: vec!["hello".into()],
            ..Default::default()
        }
    }

    async fn on_init(&mut self, _client: &mut VynkorClient) -> Result<(), VynkorError> {
        println!("[{{name}}] registered");
        Ok(())
    }

    async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VynkorError> {
        match envelope.payload {
            Some(envelope::Payload::ActionRequest(req)) if req.action == "hello" => {
                Ok(Some(Envelope {
                    payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                        action_id: req.action_id,
                        status: ActionStatus::ActionOk as i32,
                        data_json: br#"{"message":"hello from {{name}}}"}"#.to_vec(),
                        error: String::new(),
                    })),
                    ..Default::default()
                }))
            }
            Some(envelope::Payload::ActionRequest(req)) => Ok(Some(Envelope {
                payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                    action_id: req.action_id,
                    status: ActionStatus::ActionNotFound as i32,
                    data_json: Vec::new(),
                    error: format!("unknown action: {}", req.action),
                })),
                ..Default::default()
            })),
            _ => Ok(None),
        }
    }

    async fn on_shutdown(&mut self) -> Result<(), VynkorError> {
        println!("[{{name}}] shutting down");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), VynkorError> {
    App.run().await
}
