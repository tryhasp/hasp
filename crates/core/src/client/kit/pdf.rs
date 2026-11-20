use qrcode::{Color, EcLevel, QrCode};

use crate::CoreError;

const WIDTH: f64 = 595.0;
const HEIGHT: f64 = 842.0;
const MARGIN: f64 = 56.0;
const QR_SIDE: f64 = 170.0;
const QUIET: usize = 4;

pub(super) struct Page<'a> {
    pub title: &'a str,
    pub subtitle: &'a str,
    pub rows: &'a [(&'static str, &'a str)],
    pub warnings: &'a [&'a str],
    pub qr: &'a [u8],
}

fn latin1(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let code = u32::from(ch);
        let byte = match code {
            0x20..=0x7e | 0xa1..=0xff => u8::try_from(code).unwrap_or(b'?'),
            0xa0 => b' ',
            _ => b'?',
        };
        if matches!(byte, b'(' | b')' | b'\\') {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out
}

#[derive(Clone, Copy)]
struct Face {
    font: &'static str,
    size: f64,
}

const TITLE: Face = Face {
    font: "F2",
    size: 22.0,
};
const BODY: Face = Face {
    font: "F1",
    size: 10.0,
};
const LABEL: Face = Face {
    font: "F1",
    size: 9.0,
};
const VALUE: Face = Face {
    font: "F3",
    size: 13.0,
};

fn show(out: &mut Vec<u8>, face: Face, at: (f64, f64), text: &str) {
    let Face { font, size } = face;
    let (x, y) = at;
    out.extend_from_slice(format!("BT /{font} {size} Tf {x} {y} Td (").as_bytes());
    out.extend_from_slice(&latin1(text));
    out.extend_from_slice(b") Tj ET\n");
}

fn rule(out: &mut Vec<u8>, x: f64, y: f64, length: f64) {
    out.extend_from_slice(format!("0.5 w {x} {y} m {} {y} l S\n", x + length).as_bytes());
}

fn draw_qr(out: &mut Vec<u8>, payload: &[u8], right: f64, top: f64) -> Result<(), CoreError> {
    let code = QrCode::with_error_correction_level(payload, EcLevel::M)
        .map_err(|_| CoreError::Internal("the kit does not fit a QR code"))?;
    let width = code.width();
    let cells = code.to_colors();
    let unit = QR_SIDE / f64::from(u32::try_from(width + 2 * QUIET).unwrap_or(1));
    let left = right - QR_SIDE;
    for row in 0..width {
        let mut column = 0;
        while column < width {
            if cells[row * width + column] != Color::Dark {
                column += 1;
                continue;
            }
            let start = column;
            while column < width && cells[row * width + column] == Color::Dark {
                column += 1;
            }
            let x = left + unit * f64::from(u32::try_from(start + QUIET).unwrap_or(0));
            let y = top - unit * f64::from(u32::try_from(row + QUIET + 1).unwrap_or(0));
            let w = unit * f64::from(u32::try_from(column - start).unwrap_or(0));
            out.extend_from_slice(format!("{x:.2} {y:.2} {w:.2} {unit:.2} re f\n").as_bytes());
        }
    }
    Ok(())
}

fn content(page: &Page<'_>) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    show(
        &mut out,
        TITLE,
        (MARGIN, HEIGHT - MARGIN - 10.0),
        page.title,
    );
    show(
        &mut out,
        BODY,
        (MARGIN, HEIGHT - MARGIN - 30.0),
        page.subtitle,
    );
    let mut y = HEIGHT - MARGIN - 80.0;
    for (label, value) in page.rows {
        show(&mut out, LABEL, (MARGIN, y), label);
        if value.is_empty() {
            rule(&mut out, MARGIN, y - 26.0, WIDTH - 2.0 * MARGIN);
        } else {
            show(&mut out, VALUE, (MARGIN, y - 18.0), value);
        }
        y -= 52.0;
    }
    y -= 10.0;
    for line in page.warnings {
        show(&mut out, BODY, (MARGIN, y), line);
        y -= 16.0;
    }
    let qr_top = y - 20.0;
    show(
        &mut out,
        LABEL,
        (MARGIN, qr_top - 12.0),
        "Scan with the Hasp app to add a device.",
    );
    draw_qr(&mut out, page.qr, MARGIN + QR_SIDE, qr_top)?;
    Ok(out)
}

pub(super) fn render(page: &Page<'_>) -> Result<Vec<u8>, CoreError> {
    let stream = content(page)?;
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let fonts = [
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
    ];
    let mut objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {WIDTH} {HEIGHT}] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> /Contents 7 0 R >>"
        )
        .into_bytes(),
    ];
    objects.extend(fonts.iter().map(|font| font.as_bytes().to_vec()));
    let mut body = format!("<< /Length {} >>\nstream\n", stream.len()).into_bytes();
    body.extend_from_slice(&stream);
    body.extend_from_slice(b"endstream");
    objects.push(body);
    for (index, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        out.extend_from_slice(object);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    Ok(out)
}
