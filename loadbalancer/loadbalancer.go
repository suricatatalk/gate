package loadbalancer

type service struct {
	URL     string
	Service string
	load    int64
}

type LoadBalancer interface {
	GetServiceURL(serviceName string) string
}

type SimpleLoadBalancer struct {
	serviceMap map[string][]service
}

func New() {

}

func (lb *SimpleLoadBalancer) GetServiceURL(serviceName string) string {
	services := lb.serviceMap[serviceName]

}

func selectLeastUsed(services []service) service {
	chosenService := services[0]
	for _, s := range services {
		if chosenService.load > s.load {
			chosenService = s
		}
	}
	return chosenService
}
