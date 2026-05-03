import LoginIcon from '@mui/icons-material/Login';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import { FormEvent, useState } from 'react';
import { LoginDraft, RegisterDraft } from '../../types/contract';

interface AuthFormProps {
  onLogin: (draft: LoginDraft) => Promise<unknown>;
  onRegister: (draft: RegisterDraft) => Promise<unknown>;
  onCancel: () => void;
}

const AuthForm = ({ onLogin, onRegister, onCancel }: AuthFormProps) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [username, setUsername] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (mode === 'login') {
        await onLogin({ email, password });
      } else {
        await onRegister({
          email,
          password,
          passwordConfirm,
          username: username || email,
          firstName,
          lastName,
        });
      }
      onCancel();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Не удалось выполнить вход');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      {error && <div className="form-error">{error}</div>}

      <div className="segmented-control full-span">
        <button
          className={mode === 'login' ? 'active' : ''}
          onClick={() => setMode('login')}
          type="button"
        >
          Вход
        </button>
        <button
          className={mode === 'register' ? 'active' : ''}
          onClick={() => setMode('register')}
          type="button"
        >
          Регистрация
        </button>
      </div>

      {mode === 'register' && (
        <>
          <label>
            <span>Имя</span>
            <input onChange={(event) => setFirstName(event.target.value)} value={firstName} />
          </label>
          <label>
            <span>Фамилия</span>
            <input onChange={(event) => setLastName(event.target.value)} value={lastName} />
          </label>
          <label className="full-span">
            <span>Логин</span>
            <input onChange={(event) => setUsername(event.target.value)} value={username} />
          </label>
        </>
      )}

      <label className="full-span">
        <span>Email</span>
        <input
          autoComplete="email"
          onChange={(event) => setEmail(event.target.value)}
          type="email"
          value={email}
        />
      </label>

      <label className={mode === 'login' ? 'full-span' : ''}>
        <span>Пароль</span>
        <input
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          value={password}
        />
      </label>

      {mode === 'register' && (
        <label>
          <span>Повтор пароля</span>
          <input
            autoComplete="new-password"
            onChange={(event) => setPasswordConfirm(event.target.value)}
            type="password"
            value={passwordConfirm}
          />
        </label>
      )}

      <div className="form-actions full-span">
        <button className="secondary-button" onClick={onCancel} type="button">
          Отмена
        </button>
        <button className="primary-button" disabled={loading} type="submit">
          {mode === 'login' ? <LoginIcon fontSize="small" /> : <PersonAddIcon fontSize="small" />}
          <span>{mode === 'login' ? 'Войти' : 'Создать аккаунт'}</span>
        </button>
      </div>
    </form>
  );
};

export default AuthForm;
