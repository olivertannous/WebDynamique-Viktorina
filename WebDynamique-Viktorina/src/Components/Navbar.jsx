import * as ReactBootstrap from "react-bootstrap"
import Typography from '@material-ui/core/Typography';

import SignUp from "./SignUp";

function Navbar() {
    return (
      <Typography>
      <div className="App">
          <ReactBootstrap.Navbar collapseOnSelect expand="lg" bg="danger" variant="dark" >
          <ReactBootstrap.Navbar.Brand href="/home">Viktorina-AI</ReactBootstrap.Navbar.Brand>
          <ReactBootstrap.Navbar.Toggle aria-controls="responsive-navbar-nav" />
          <ReactBootstrap.Navbar.Collapse id="responsive-navbar-nav">

          <ReactBootstrap.Nav className="mr-auto">
          <ReactBootstrap.Nav.Link href="/about-us">About Us</ReactBootstrap.Nav.Link>
          <ReactBootstrap.Nav.Link href="/pricing">Pricing</ReactBootstrap.Nav.Link>
       
          </ReactBootstrap.Nav>

          <ReactBootstrap.Nav>
          <ReactBootstrap.Nav.Link href="/signin" >Log in</ReactBootstrap.Nav.Link>
          <ReactBootstrap.Nav.Link eventKey={2} href="/signup">Sign Up</ReactBootstrap.Nav.Link>
          </ReactBootstrap.Nav>
          </ReactBootstrap.Navbar.Collapse>
          </ReactBootstrap.Navbar>
        <br></br>

      <br></br>
      
      </div>
      </Typography>
    );
  }
  
  export default Navbar;