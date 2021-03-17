import React, { Component } from "react";
import { render } from "react-dom";
import {BrowserRouter as Router,Switch,Route,Link,Redirect} from "react-router-dom";
import Home from "./Components/Home";
import Pricing from "./Components/Pricing";
import SignUp from "./Components/SignUp";
import SignIn from "./Components/SignIn";
import AboutUs from "./Components/AboutUs";
import { ThemeProvider, createMuiTheme } from '@material-ui/core/styles';

const theme = createMuiTheme({
  typography: {
    fontFamily: [
      'Times New Roman',
    ].join(','),
  },
});


class App extends Component {
  constructor() {
    super();
    this.state = {
      name: "React",
      isUserAuthenticated: true
    };
  }

  render() {
    return (
      <ThemeProvider theme={theme}>
      <div>
        <Router>
          <div>         
            <Switch>
              <Route exact path="/" render={() => {
                    return (
                      this.state.isUserAuthenticated ?
                      <Redirect to="/home" /> :
                      <Redirect to="/login" /> 
                    
                    )
                }}
              />
               <Route exact path="/home" component={Home} />
              <Route exact path="/signup" component={SignUp} />
              <Route path="/pricing" component={Pricing} />
              <Route path="/signin" component={SignIn} />
              <Route path="/about-us" component={AboutUs} />
            </Switch>
          </div>
        </Router>
      </div>
      </ThemeProvider>
    );
  }
  
}
render(<App />, document.getElementById("root"));
export default App;


