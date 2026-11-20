import { mount } from '../ui/mount.tsx';
import { PasskeyApp } from './passkey-app.tsx';

const id = new URLSearchParams(window.location.search).get('id') ?? '';

mount(<PasskeyApp id={id} />);
