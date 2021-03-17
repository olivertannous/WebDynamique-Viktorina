import React from 'react';
import Container from '@material-ui/core/Container';
import Navbar from './Navbar';
import Typography from '@material-ui/core/Typography';
import Link from '@material-ui/core/Link';
import { Button, TextField } from '@material-ui/core';
import { withStyles } from "@material-ui/core/styles";
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';



function Copyright() {
  return (
    <Typography variant="body2" color="textSecondary" align="center">
      {'Copyright © '}
      <Link color="inherit" href="/home">
        Viktorina-AI
      </Link>{' '}
      {new Date().getFullYear()}
      {'.'}
    </Typography>
  );
}

const styles = theme => ({
    footer: {
    borderTop: `1px solid ${theme.palette.divider}`,
    marginTop: theme.spacing(8),
    paddingTop: theme.spacing(3),
    paddingBottom: theme.spacing(3),
    [theme.breakpoints.up('sm')]: {
      paddingTop: theme.spacing(6),
      paddingBottom: theme.spacing(6),
    },
  },
  title: {
    fontSize: 14,
  },
  pos: {
    marginBottom: 12,
  },
});


class Home extends React.Component
{
  constructor(){
    super();
    this.state = {
      items: [],
      isLoaded: false,
      isAuthenticated: false,
      value:''
    };
    this.handleChange = this.handleChange.bind(this);
}

login = () => {
  this.setState({ isAuthenticated: true });
}

logout = () => {
  this.setState({ isAuthenticated: false });
}

handleChange(event) {
  this.setState({value: event.target.value});  
}
 

 generate() {
  const requestOptions = {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'togenerate='+this.state.value
  };
  fetch('/generate-questions', requestOptions).then(response=>response.json()).then(data=>{this.setState({items:data,isLoaded:true});});
}
  
   render(){
    const { items } = this.state;
    const { classes } = this.props;
  return (
    <div>
      
    <Navbar></Navbar> 
    <Typography>
    <Container maxWidth="md" component="main">
    <h4>Convert your course into questions that may be part of your next exam.<br></br>Good luck!</h4>
        <textarea class="form-control" id="pastedtext" name="togenerate" rows="10" placeholder="Paste your text here" onChange={this.handleChange} ></textarea>
        <Button
            type="submit"
            fullWidth
            variant="contained"
            color="primary"
            onClick={this.generate.bind(this)}>
            Generate
          </Button>
          <div>
            <hr></hr>
            <br></br>
    <h3>Your questions and answers will appear below:</h3>
    
  </div>

  {items.map(item => {
  return <Card className={classes.root}>
  <CardContent>   
    <Typography variant="h5" component="h2">
      <b>Question:</b>
    </Typography>
    
    <Typography variant="h6" component="p" >
    {item.question}
    </Typography>
    <div ID="SectionName" STYLE="display:block">
    <Typography variant="h5" component="h2" >
      <b>Answer:</b>
    </Typography>
    <Typography variant="h6" component="p">
    <i>{item.answer}</i>
    </Typography>
    </div>
  </CardContent>
</Card>
})}
  

    </Container>
    </Typography>
    <Container maxWidth="md" component="footer" >
      <Copyright />
      </Container>
    </div>
  );
  }
}

//export default Home;

export default withStyles(styles, { withTheme: true })(Home);

//{items.map(item => (
  //<li key={item.id}>
    //<h3></h3>
    //<p>{item.question}</p>
  //</li>
//))}


