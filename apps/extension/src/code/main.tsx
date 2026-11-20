import { mount } from '../ui/mount.tsx';
import { CodeApp } from './code-app.tsx';

const id = new URLSearchParams(window.location.search).get('id') ?? '';

mount(<CodeApp id={id} />);
