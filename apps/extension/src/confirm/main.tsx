import { mount } from '../ui/mount.tsx';
import { ConfirmApp } from './confirm-app.tsx';

const id = new URLSearchParams(window.location.search).get('id') ?? '';

mount(<ConfirmApp id={id} />);
