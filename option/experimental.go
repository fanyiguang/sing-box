package option

type ExperimentalOptions struct {
	ClashAPI   *ClashAPIOptions   `json:"clash_api,omitempty"`
	V2RayAPI   *V2RayAPIOptions   `json:"v2ray_api,omitempty"`
	Controller *ControllerOptions `json:"controller,omitempty"`
}
