//! NeXX — чисто-Rust Android-приложение (NativeActivity + egui/wgpu).
//! Весь UI и вся логика — наш код; nexxrust подключён как rlib напрямую.
//!
//! ВАЖНО (баг запуска): на Android winit отдаёт raw-window-handle **только**
//! после события `Event::Resumed` (до него `native_window == null`, winit
//! возвращает `HandleError::Unavailable`). Поэтому wgpu-поверхность, адаптер
//! и устройство создаются внутри обработчика `Resumed`, а не сразу после
//! `create_window()`. Иначе приложение падало при старте:
//!   `surface: CreateSurfaceError { inner: RawHandle(Unavailable) }`.

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

/// GPU-состояние приложения. Пересоздаётся при `Resumed` (native window меняется).
struct Gfx {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    format: wgpu::TextureFormat,
    alpha_mode: wgpu::CompositeAlphaMode,
    painter: egui_wgpu::Renderer,
    state: egui_winit::State,
}

/// Создаёт GPU-контекст, перебирая бэкенды: Vulkan → OpenGL ES.
/// Раньше падали на первом же бэкенде, если он не умеет делать surface.
fn create_gfx(window: &Arc<winit::window::Window>, ctx: &egui::Context) -> Result<Gfx, String> {
    let mut last_err = String::new();
    for backends in [wgpu::Backends::VULKAN, wgpu::Backends::GL] {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends,
            ..Default::default()
        });
        let surface = match instance.create_surface(window.clone()) {
            Ok(s) => s,
            Err(e) => {
                last_err = format!("surface [{backends:?}]: {e}");
                log::warn!("NeXX: {last_err}, пробуем следующий бэкенд");
                continue;
            }
        };
        let adapter = match pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: Some(&surface),
            force_fallback_adapter: false,
        })) {
            Some(a) => a,
            None => {
                last_err = format!("adapter [{backends:?}]: не найден");
                log::warn!("NeXX: {last_err}, пробуем следующий бэкенд");
                continue;
            }
        };
        let (device, queue) = match pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("nexx"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        )) {
            Ok(d) => d,
            Err(e) => {
                last_err = format!("device [{backends:?}]: {e}");
                log::warn!("NeXX: {last_err}, пробуем следующий бэкенд");
                continue;
            }
        };

        let caps = surface.get_capabilities(&adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(caps.formats[0]);
        let alpha_mode = caps.alpha_modes[0];
        configure_surface(&device, &surface, format, alpha_mode, window.inner_size());

        let mut state = egui_winit::State::new(
            ctx.clone(),
            egui::ViewportId::ROOT,
            window,
            Some(window.scale_factor() as f32),
            None,
            None,
        );
        state.take_egui_input(window);
        let painter = egui_wgpu::Renderer::new(&device, format, None, 1, false);
        log::info!(
            "NeXX: GPU готов [{backends:?}], формат {format:?}, alpha {alpha_mode:?}, size {:?}",
            window.inner_size()
        );
        return Ok(Gfx {
            surface,
            device,
            queue,
            format,
            alpha_mode,
            painter,
            state,
        });
    }
    Err(last_err)
}

#[no_mangle]
fn android_main(android_app: AndroidApp) {
    android_logger::init_once(
        android_logger::Config::default().with_max_level(log::LevelFilter::Info),
    );
    // Паники видно в logcat — вместо молчаливого падения.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("NeXX PANIC: {info}");
        default_hook(info);
    }));
    log::info!("NeXX rust app start");

    let event_loop = EventLoop::builder()
        .with_android_app(android_app)
        .build()
        .expect("event loop");

    let attrs = winit::window::Window::default_attributes().with_title("NeXX");
    let window = Arc::new(event_loop.create_window(attrs).expect("window"));

    let ctx = egui::Context::default();
    ctx.set_theme(egui::Theme::Dark);
    let mut app = ui::NeXXUi::new();
    let mut gfx: Option<Gfx> = None;

    let _ = event_loop.run(move |event, _elwt| match event {
        winit::event::Event::Resumed => {
            // Только здесь native window валиден — создаём GPU-контекст.
            if gfx.is_none() {
                match create_gfx(&window, &ctx) {
                    Ok(g) => gfx = Some(g),
                    Err(e) => log::error!("NeXX: GPU недоступен: {e}"),
                }
            }
        }
        winit::event::Event::Suspended => {
            // native window уничтожен — освобождаем GPU-ресурсы.
            gfx = None;
        }
        winit::event::Event::WindowEvent { event, .. } => {
            if let Some(g) = gfx.as_mut() {
                let _ = g.state.on_window_event(&window, &event);
                match event {
                    winit::event::WindowEvent::Resized(s) => {
                        configure_surface(&g.device, &g.surface, g.format, g.alpha_mode, s)
                    }
                    winit::event::WindowEvent::RedrawRequested => {
                        let size = window.inner_size();
                        let input = g.state.take_egui_input(&window);
                        ctx.begin_pass(input);
                        app.ui(&ctx);
                        let out = ctx.end_pass();
                        g.state
                            .handle_platform_output(&window, out.platform_output.clone());
                        let clipped = ctx.tessellate(out.shapes, out.pixels_per_point);
                        let screen = egui_wgpu::ScreenDescriptor {
                            size_in_pixels: [size.width.max(1), size.height.max(1)],
                            pixels_per_point: out.pixels_per_point,
                        };
                        for (id, img) in out.textures_delta.set {
                            g.painter.update_texture(&g.device, &g.queue, id, &img);
                        }
                        for id in out.textures_delta.free {
                            g.painter.free_texture(&id);
                        }
                        let frame = match g.surface.get_current_texture() {
                            Ok(f) => f,
                            Err(_) => return,
                        };
                        let view = frame
                            .texture
                            .create_view(&wgpu::TextureViewDescriptor::default());
                        let mut encoder = g
                            .device
                            .create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
                        let bufs = g
                            .painter
                            .update_buffers(&g.device, &g.queue, &mut encoder, &clipped, &screen);
                        {
                            let rpass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
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
                            g.painter.render(&rpass.forget_lifetime(), &clipped, &screen);
                        }
                        g.queue.submit(bufs);
                        g.queue.submit(Some(encoder.finish()));
                        frame.present();
                    }
                    _ => {}
                }
            }
        }
        winit::event::Event::AboutToWait => window.request_redraw(),
        _ => {}
    });
}
