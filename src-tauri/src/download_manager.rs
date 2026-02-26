// Modified DirFmtParams struct to include date parameters
#[derive(Debug, Clone)]
pub struct DirFmtParams {
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub date: String,
    // other existing fields...
}

impl DirFmtParams {
    pub fn new(year: u32, month: u32, day: u32, date: String) -> Self {
        Self { year, month, day, date, /* initialize other fields... */ }
    }
}

// Updated update_download_dir_fields_by_fmt method to support date-based paths
pub fn update_download_dir_fields_by_fmt(&self) -> String {
    format!("downloads/{}/{}/{}", self.year, self.month, self.day)
    // implement other logic using the new date fields as needed
}