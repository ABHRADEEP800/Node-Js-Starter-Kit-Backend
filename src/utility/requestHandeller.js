const requestHandler = (handellerFunction) => {
  return (req, res, next) => {
    Promise.resolve(handellerFunction(req, res, next)).catch(next);
  };
};

export default requestHandler;
