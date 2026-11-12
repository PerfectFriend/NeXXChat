//! NeXX — чисто-Rust Android-приложение (NativeActivity + egui/wgpu).
//! Весь UI и вся логика — наш код; nexxrust подключён как rlib напрямую.

use android_activity::AndroidApp;
use std::sync::Arc;
use winit::event_loop::EventLoop;
use winit::platform::android::EventLoopBuilderExtAndroid;

mod ui;

fn configure_surface(
    device: &wgpu::Device,
    surface: &wgpu::Surface<'_>,
    format: wgpu::TextureFormat,
    alpha_mode: wgpu::CompositeAlphaMode,
    s: winit::dpi::PhysicalSize<u32>,
) {
    surface.configure(
        device,
        &wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width: s.width.max(1),
            height: s.height.max(1),
            present_mode: wgpu::PresentMode::Fifo,
            alpha_mode,
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        },
    );
}

#[no_mangle]
fn android_main(android_app: AndroidApp) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );
    log::info!("NeXX rust app start");

    let event_loop = EventLoop::builder()
        .with_android_app(android_app)
        .build()
        .expect("event loop");

    let attrs = winit::window::Window::default_attributes().with_title("NeXX");
    let window = Arc::new(event_loop.create_window(attrs).expect("window"));

    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
    let surface = instance.create_surface(window.clone()).expect("surface");
    let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::LowPower,
        compatible_surface: Some(&surface),
        force_fallback_adapter: false,
    }))
    .expect("no adapter");
    let (device, queue) = pollster::block_on(adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("nexx"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::downlevel_defaults(),
            memory_hints: wgpu::MemoryHints::Performance,
        },
        None,
    ))
    .expect("device");

    let caps = surface.get_capabilities(&adapter);
    let format = caps
        .formats
        .iter()
        .copied()
        .find(|f| f.is_srgb())
        .unwrap_or(caps.formats[0]);
    let alpha_mode = caps.alpha_modes[0];
    configure_surface(&device, &surface, format, alpha_mode, window.inner_size());

    let ctx = egui::Context::default();
    ctx.set_theme(egui::Theme::Dark);
    let mut state = egui_winit::State::new(
        ctx.clone(),
        egui::ViewportId::ROOT,
        &window,
        Some(window.scale_factor() as f32),
        None,
        None,
    );
    let mut painter = egui_wgpu::Renderer::new(&device, format, None, 1, false);
    let mut app = ui::NeXXUi::new();

    let _ = event_loop.run(move |event, _elwt| match event {
        winit::event::Event::WindowEvent { event, .. } => {
            let _ = state.on_window_event(&window, &event);
            match event {
                winit::event::WindowEvent::Resized(s) => {
                    configure_surface(&device, &surface, format, alpha_mode, s)
                }
                winit::event::WindowEvent::RedrawRequested => {
                    let size = window.inner_size();
                    let input = state.take_egui_input(&window);
                    ctx.begin_pass(input);
                    app.ui(&ctx);
                    let out = ctx.end_pass();
                    state.handle_platform_output(&window, out.platform_output.clone());
                    let clipped = ctx.tessellate(out.shapes, out.pixels_per_point);
                    let screen = egui_wgpu::ScreenDescriptor {
                        size_in_pixels: [size.width.max(1), size.height.max(1)],
                        pixels_per_point: out.pixels_per_point,
                    };
                    for (id, img) in out.textures_delta.set {
                        painter.update_texture(&device, &queue, id, &img);
                    }
                    for id in out.textures_delta.free {
                        painter.free_texture(&id);
                    }
                    let frame = match surface.get_current_texture() {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    let view = frame.texture.create_view(&wgpu::TextureViewDescriptor::default());
                    let mut encoder =
                        device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
                    let bufs = painter.update_buffers(&device, &queue, &mut encoder, &clipped, &screen);
                    {
                        let mut rpass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                            label: Some("egui"),
                            color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                                view: &view,
                                resolve_target: None,
                                ops: wgpu::Operations {
                                    load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                                    store: wgpu::StoreOp::Store,
                                },
                            })],
                            depth_stencil_attachment: None,
                            timestamp_writes: None,
                            occlusion_query_set: None,
                        });
                        painter.render(&mut rpass.forget_lifetime(), &clipped, &screen);
                    }
                    queue.submit(bufs);
                    queue.submit(Some(encoder.finish()));
                    frame.present();
                }
                _ => {}
            }
        }
        winit::event::Event::AboutToWait => window.request_redraw(),
        _ => {}
    });
}
