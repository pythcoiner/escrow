#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names, unused)]
pub enum MemPoolError {
    ApiRequestFail,
    ResponseDeserializeFail,
    DataDeserializeFail,
}
