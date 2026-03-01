#[derive(Debug, Clone)]
pub struct KeyMaterialRef {
    pub key_id: String,
    pub version: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct KeyRotationPolicy {
    pub rotate_every_days: u32,
    pub overlap_days: u32,
}

impl KeyRotationPolicy {
    pub fn is_valid(self) -> bool {
        self.rotate_every_days > 0 && self.overlap_days <= self.rotate_every_days
    }
}

