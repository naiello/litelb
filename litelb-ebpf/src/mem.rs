use aya_ebpf::programs::XdpContext;

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, &'static str> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err("pointer out of range");
    }

    Ok((start + offset) as *mut T)
}
