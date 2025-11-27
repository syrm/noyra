package podman

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/samber/oops"

	"blackprism.org/noyra/internal/podman/component"
)

const podmanVersion = "v5.0.0"

func getPodmanEndpoint() string {
	return "http://localhost/" + podmanVersion + "/libpod"
}

type Client struct {
	podmanSocket string
	httpClient   *http.Client
	logger       *slog.Logger
}

type ErrStartContainer struct {
	Cause   string `json:"cause"`
	Message string `json:"message"`
}

func BuildClient(podmanSocket string, logger *slog.Logger) *Client {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", podmanSocket)
			},
		},
		Timeout: 10 * time.Second,
	}

	return &Client{
		podmanSocket: podmanSocket,
		httpClient:   httpClient,
		logger:       logger,
	}
}

func (client *Client) NetworkExists(ctx context.Context, name string) (bool, error) {
	localOops := oops.In("network_exists")

	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, getPodmanEndpoint()+"/networks/"+name+"/exists", nil)

	if errReq != nil {
		return false, localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return false, localOops.Wrap(errGet)
	}

	return resp.StatusCode == http.StatusNoContent, nil
}

func (client *Client) ListNetworks(ctx context.Context, filters map[string][]string) ([]component.Network, error) {
	localOops := oops.In("list_networks")

	filtersJSON, errMarshal := json.Marshal(filters)

	if errMarshal != nil {
		return nil, localOops.Wrap(errMarshal)
	}

	req, errReq := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		getPodmanEndpoint()+"/networks/json?"+"filters="+url.QueryEscape(string(filtersJSON)),
		nil,
	)

	if errReq != nil {
		return nil, localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return nil, localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return nil, errHandleError
	}

	body, errReadBody := io.ReadAll(resp.Body)

	if errReadBody != nil {
		return nil, localOops.Wrapf(errReadBody, "read body")
	}

	var networks []component.Network

	errJson := json.Unmarshal(body, &networks)

	if errJson != nil {
		return nil, localOops.Wrapf(errJson, "unmarshal")
	}

	return networks, nil
}

func (client *Client) CreateNetwork(ctx context.Context, network component.Network) error {
	localOops := oops.In("create_network").With("name", network.Name)

	networkJSON, errMarshal := json.Marshal(network)

	if errMarshal != nil {
		return localOops.Wrap(errMarshal)
	}

	req, errReq := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		getPodmanEndpoint()+"/networks/create",
		strings.NewReader(string(networkJSON)),
	)

	if errReq != nil {
		return localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return errHandleError
	}

	return nil
}

func (client *Client) RemoveNetwork(ctx context.Context, name string) (bool, error) {
	localOops := oops.In("remove_network")

	req, errReq := http.NewRequestWithContext(ctx, http.MethodDelete, getPodmanEndpoint()+"/networks/"+name, nil)

	if errReq != nil {
		return false, localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return false, localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return false, errHandleError
	}

	return resp.StatusCode == http.StatusOK, nil
}

func (client *Client) ListImages(ctx context.Context) error {
	localOops := oops.In("list_images")

	req, errReq := http.NewRequestWithContext(ctx, http.MethodDelete, getPodmanEndpoint()+"/images/json", nil)

	if errReq != nil {
		return localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return errHandleError
	}

	body, errReadBody := io.ReadAll(resp.Body)

	if errReadBody != nil {
		return localOops.Wrapf(errReadBody, "read body")
	}

	var images []component.Image

	println(string(body))

	errJson := json.Unmarshal(body, &images)

	if errJson != nil {
		return localOops.Wrapf(errJson, "unmarshal")
	}

	for _, image := range images {
		fmt.Printf("image:\n\tID\t%s\n\tNames: %+v\n", image.ID, image.Names)
	}

	return nil
}

func (client *Client) PullImage(ctx context.Context, image string) error {
	localOops := oops.In("pull_image").With("image", image)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, getPodmanEndpoint()+"/images/create?fromImage="+image, nil)

	if errReq != nil {
		return localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return errHandleError
	}

	_, errReadBody := io.ReadAll(resp.Body)

	if errReadBody != nil {
		return localOops.Wrapf(errReadBody, "read body")
	}

	return nil
}

func (client *Client) ListContainers(
	ctx context.Context,
	all bool,
	filters map[string][]string,
) ([]component.Container, error) {
	localOops := oops.In("list_containers")

	filtersJSON, errMarshal := json.Marshal(filters)

	if errMarshal != nil {
		return nil, localOops.Wrap(errMarshal)
	}

	req, errReq := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		getPodmanEndpoint()+
			"/containers/json?all="+strconv.FormatBool(all)+
			"&filters="+string(filtersJSON),
		nil,
	)

	if errReq != nil {
		return nil, localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return nil, localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return nil, errHandleError
	}

	body, errReadBody := io.ReadAll(resp.Body)

	if errReadBody != nil {
		return nil, localOops.Wrapf(errReadBody, "read body")
	}

	var containers []component.Container

	errJson := json.Unmarshal(body, &containers)

	if errJson != nil {
		return nil, localOops.With("body", body).Wrapf(errJson, "unmarshal")
	}

	return containers, nil
}

func (client *Client) InspectContainer(ctx context.Context, name string) (component.ContainerInspected, error) {
	localOops := oops.In("inspect_container")

	req, errReq := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		getPodmanEndpoint()+
			"/containers/"+name+"/json",
		nil,
	)

	if errReq != nil {
		return component.ContainerInspected{}, localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return component.ContainerInspected{}, localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return component.ContainerInspected{}, errHandleError
	}

	body, errReadBody := io.ReadAll(resp.Body)

	if errReadBody != nil {
		return component.ContainerInspected{}, localOops.Wrapf(errReadBody, "read body")
	}

	var container component.ContainerInspected

	errJson := json.Unmarshal(body, &container)

	if errJson != nil {
		return component.ContainerInspected{}, localOops.With("body", body).Wrapf(errJson, "unmarshal")
	}

	return container, nil
}

func (client *Client) StartContainer(ctx context.Context, name string) error {
	localOops := oops.In("start_container").With("name", name)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, getPodmanEndpoint()+"/containers/"+name+"/start", nil)

	if errReq != nil {
		return localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return errHandleError
	}

	return nil
}

func (client *Client) StopContainer(ctx context.Context, name string) error {
	localOops := oops.In("stop_container").With("name", name)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodPost, getPodmanEndpoint()+"/containers/"+name+"/stop", nil)

	if errReq != nil {
		return localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return errHandleError
	}

	return nil
}

func (client *Client) RemoveContainer(ctx context.Context, name string) error {
	localOops := oops.In("remove_container").With("name", name)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodDelete, getPodmanEndpoint()+"/containers/"+name, nil)

	if errReq != nil {
		return localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return errHandleError
	}

	return nil
}

func (client *Client) CreateContainer(ctx context.Context, container component.ContainerRequest) (string, error) {
	localOops := oops.In("create_container").With("name", container.Name)

	// @TODO a deplacer c'est pas sa responsabilité
	container.Netns = component.ContainerRequestNetns{
		Nsmode: "bridge",
	}
	container.NoNewPrivileges = true
	container.CapDrop = []string{"ALL"}
	//container.Userns = component.ContainerRequestUserns{
	//	Nsmode: "keep-id",
	//	Value:  "",
	//}
	//container.User = fmt.Sprintf("%d", os.Getuid())

	//containerSecurityConfig := specgen.ContainerSecurityConfig{
	//	CapDrop:         []string{"ALL"},
	//	NoNewPrivileges: &trueValue,
	//}
	//
	//if containerRequest.UserNS {
	//	containerSecurityConfig.User = fmt.Sprintf("%d", os.Getuid())
	//	containerSecurityConfig.UserNS = specgen.Namespace{NSMode: specgen.KeepID}
	//}

	containerJSON, errMarshal := json.Marshal(container, json.OmitZeroStructFields(true))

	if errMarshal != nil {
		return "", localOops.Wrap(errMarshal)
	}

	println(string(containerJSON))

	req, errReq := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		getPodmanEndpoint()+"/containers/create",
		strings.NewReader(string(containerJSON)),
	)

	if errReq != nil {
		return "", localOops.Wrapf(errReq, "request")
	}

	resp, errGet := client.httpClient.Do(req)

	if errGet != nil {
		return "", localOops.Wrap(errGet)
	}

	errHandleError := handleErrorResponse(localOops, resp)

	if errHandleError != nil {
		return "", errHandleError
	}

	body, errReadBody := io.ReadAll(resp.Body)

	if errReadBody != nil {
		localOops.With("body", body)
	}

	type response struct {
		ID string `json:"Id"`
	}

	var createResponse response

	errJson := json.Unmarshal(body, &createResponse)

	if errJson != nil {
		return "", localOops.Wrapf(errJson, "unmarshal")
	}

	return createResponse.ID, nil
}

func handleErrorResponse(localOops oops.OopsErrorBuilder, resp *http.Response) error {
	if resp.StatusCode >= 400 {
		body, errReadBody := io.ReadAll(resp.Body)

		if errReadBody != nil {
			localOops.With("body", body)
		}

		type errorResponse struct {
			Message string `json:"message"`
			Cause   string `json:"cause"`
		}

		var errorResp errorResponse

		errJson := json.Unmarshal(body, &errorResp)

		if errJson != nil {
			return localOops.Code(strconv.Itoa(resp.StatusCode)).New("request")
		}

		return localOops.Code(strconv.Itoa(resp.StatusCode)).With("error_response", errorResp).New("request")
	}

	return nil
}
