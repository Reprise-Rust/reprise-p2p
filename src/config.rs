pub struct ServerConfig {
    pub tcp_handler_port: Option<u16>,
    pub udp_handler_port: Option<u16>,
}

impl ServerConfig {
    pub fn udp_only() -> Self {
        Self {
            udp_handler_port: Some(47002),
            tcp_handler_port: None,
        }
    }

    pub fn tcp_only() -> Self {
        Self {
            udp_handler_port: None,
            tcp_handler_port: Some(47002),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_handler_port: Some(47002),
            udp_handler_port: Some(47002),
        }
    }
}
