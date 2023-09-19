import './css/App.css';
import './css/welcome.css';
import './css/User/Login.css';
import './css/User/FindId.css';
import './css/User/FindPw.css';
import './css/User/Register.css';
import { UploadArea, Banner } from './Routes/Main.js';
import Test from './Routes/Test';
import Result from './Routes/Result.js';
import { Header } from './Components/Header.js';
import { Routes, Route } from "react-router-dom";
import Login from './Routes/User/Login';
import { FindId, ShowId } from './Routes/User/FindId';
import { FindPw, ResetPw, LoginResetPw } from './Routes/User/FindPw';
import Register from './Routes/User/Register.js';
import NoPage from './Routes/ErrorPage';
import Welcome from './Routes/Welcome';

// 주석 용도 내용 전달
// 1. 회원가입 / 로그인 / 아이디찾기 / 비밀번호 찾기 / 비밀번호재설정 페이지
// 1.1 input value backend로 보내기 구현
// 3. OAuth2
// 

function App() {

  return (
    <div className="App">

      <Routes>
        <Route path="/" element={
          <>
            <Welcome />
          </>
        } />

        <Route path="/main" element={
          <>
            <Header />
            <UploadArea />
            <Banner />
          </>
        } />

        <Route path="/result" element={
          <>
            <Header />
            <Result />
          </>
        } />

        <Route path="/login" element={
          <>
            <Login />
          </>
        } />

        <Route path="/register" element={
          <>
            <Register />
          </>
        } />

        <Route path="/findid" element={
          <>
            <FindId />
          </>
        } />

        <Route path="/findpw" element={
          <>
            <FindPw />
          </>
        } />

        <Route path="/resetpw" element={
          <>
            <ResetPw />
          </>
        } />

        <Route path="/loginresetpw" element={
          <>
            <LoginResetPw />
          </>
        } />

        <Route path="/showid" element={
          <>
            <ShowId />
          </>
        } />
        <Route path="/test" element={
          <>
            <Test />
          </>
        } />
        <Route path="*" element={
          <>
            <NoPage />
          </>
        } />

      </Routes>

    </div>
  );
}

export default App;

