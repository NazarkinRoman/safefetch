use std::io::Cursor;

use anyhow::{Context, Result as AnyResult, bail};
use image::{ImageFormat, ImageReader};
use url::Url;

use crate::{ImageInspection, ImageInspectionOptions};

const MAX_IMAGE_DIMENSION: u32 = 16_384;
const MAX_IMAGE_PIXELS: u64 = 40_000_000;

pub(crate) fn normalize_mime_type(value: Option<&String>) -> String {
  value
    .and_then(|value| value.split(';').next())
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .unwrap_or("application/octet-stream")
    .to_string()
}

pub(crate) fn infer_mime_type_from_extension(url: &Url) -> Option<&'static str> {
  let extension = url.path_segments()?.next_back()?.rsplit_once('.')?.1;
  match extension.to_ascii_lowercase().as_str() {
    "pdf" => Some("application/pdf"),
    "mp3" => Some("audio/mpeg"),
    "opus" => Some("audio/opus"),
    "ogg" => Some("audio/ogg"),
    "aac" => Some("audio/aac"),
    "m4a" => Some("audio/aac"),
    "flac" => Some("audio/flac"),
    "ogv" => Some("video/ogg"),
    "wav" => Some("audio/wav"),
    "png" => Some("image/png"),
    "jpeg" | "jpg" => Some("image/jpeg"),
    "webp" => Some("image/webp"),
    "txt" | "md" => Some("text/plain"),
    "mov" => Some("video/mov"),
    "mpeg" => Some("video/mpeg"),
    "mp4" => Some("video/mp4"),
    "avi" => Some("video/avi"),
    "wmv" => Some("video/wmv"),
    "flv" => Some("video/flv"),
    _ => None,
  }
}

pub fn inspect_image(input: &[u8], options: ImageInspectionOptions) -> AnyResult<ImageInspection> {
  let inspection = parse_image_header(input).context("failed to decode image")?;
  validate_image_dimensions(&inspection, options)?;
  Ok(inspection)
}

fn validate_image_dimensions(image: &ImageInspection, options: ImageInspectionOptions) -> AnyResult<()> {
  let max_width = options.max_width.unwrap_or(MAX_IMAGE_DIMENSION);
  let max_height = options.max_height.unwrap_or(MAX_IMAGE_DIMENSION);
  let max_pixels = u64::from(options.max_pixels.unwrap_or(MAX_IMAGE_PIXELS as u32));
  if image.width == 0 || image.height == 0 {
    bail!("failed to decode image");
  }
  if image.width > max_width || image.height > max_height {
    bail!("image dimensions exceed limit");
  }
  if u64::from(image.width) * u64::from(image.height) > max_pixels {
    bail!("image pixel count exceeds limit");
  }
  Ok(())
}

fn parse_image_header(input: &[u8]) -> AnyResult<ImageInspection> {
  let format = ::image::guess_format(input).context("unsupported image format")?;
  let mime_type = image_mime_type(format).context("unsupported image format")?;
  let (width, height) = ImageReader::with_format(Cursor::new(input), format)
    .into_dimensions()
    .context("failed to decode image")?;
  Ok(ImageInspection {
    mime_type: mime_type.to_string(),
    width,
    height,
  })
}

fn image_mime_type(format: ImageFormat) -> Option<&'static str> {
  match format {
    ImageFormat::Png => Some("image/png"),
    ImageFormat::Jpeg => Some("image/jpeg"),
    ImageFormat::Gif => Some("image/gif"),
    ImageFormat::WebP => Some("image/webp"),
    ImageFormat::Bmp => Some("image/bmp"),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn inspects_png_dimensions_without_decode() {
    let png = base64_simd::STANDARD
      .decode_to_vec(b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jfJ8AAAAASUVORK5CYII=")
      .unwrap();
    let inspected = inspect_image(
      &png,
      ImageInspectionOptions {
        max_width: None,
        max_height: None,
        max_pixels: None,
      },
    )
    .unwrap();
    assert_eq!(inspected.mime_type, "image/png");
    assert_eq!(inspected.width, 1);
    assert_eq!(inspected.height, 1);
  }

  #[test]
  fn rejects_oversized_dimensions() {
    let png = [
      b"\x89PNG\r\n\x1a\n".as_slice(),
      &[0, 0, 0, 13],
      b"IHDR".as_slice(),
      &100_000u32.to_be_bytes(),
      &100_000u32.to_be_bytes(),
      &[8, 6, 0, 0, 0],
      &[0, 0, 0, 0],
      &[0, 0, 0, 0],
      b"IEND".as_slice(),
      &[0, 0, 0, 0],
    ]
    .concat();
    let result = inspect_image(
      &png,
      ImageInspectionOptions {
        max_width: Some(10_000),
        max_height: None,
        max_pixels: None,
      },
    );
    assert!(result.is_err());
  }
}
